"""Small dependency-free LockGate client for Python 3.10+."""

import json
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

__version__ = "0.1.0"


class LockGateError(RuntimeError):
    def __init__(self, message: str, code: str = "LOCKGATE_ERROR"):
        super().__init__(message)
        self.code = code


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # Never forward the bearer token to another origin.


class LockGateClient:
    def __init__(self, url: str, token: str, poll_interval: float = 3.0, request_timeout: float = 15.0):
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc or parsed.username or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise LockGateError("LOCKGATE_URL must be an HTTP(S) origin", "CONFIG")
        if not token:
            raise LockGateError("LOCKGATE_TOKEN is required", "CONFIG")
        self.url = f"{parsed.scheme}://{parsed.netloc}"
        self.token = token
        self.poll_interval = max(poll_interval, 3.0)
        self.request_timeout = request_timeout
        self.opener = urllib.request.build_opener(_NoRedirect)

    def get_config(self, startup_timeout: float = 600.0) -> dict[str, str]:
        deadline = time.monotonic() + startup_timeout
        instance_key = str(uuid.uuid4())
        access = self._request("POST", "/api/v1/access", {}, instance_key, deadline)
        while True:
            status = access.get("status")
            if status == "approved":
                bundles = list((access.get("secrets") or {}).values())
                if len(bundles) != 1 or not isinstance(bundles[0], dict):
                    raise LockGateError("Expected exactly one configured secret bundle", "INVALID_RESPONSE")
                return bundles[0]
            if status == "denied":
                raise LockGateError("Access denied by administrator", "DENIED")
            if status == "revoked":
                access = self._request("POST", "/api/v1/access", {}, instance_key, deadline)
                continue
            if status != "waiting_approval":
                raise LockGateError(f"Unexpected access status: {status!r}", "INVALID_RESPONSE")
            request_id = access.get("request_id")
            if not isinstance(request_id, str) or not request_id.replace("-", "").replace("_", "").isalnum():
                raise LockGateError("Server returned an invalid request ID", "INVALID_RESPONSE")
            delay = max(self.poll_interval, float(access.get("retry_after") or 0))
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise LockGateError("Startup approval timed out", "TIMEOUT")
            time.sleep(min(delay, remaining))
            access = self._request("GET", "/api/v1/access/" + urllib.parse.quote(request_id, safe=""), None, None, deadline)

    def _request(self, method, path, body, instance_key, deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise LockGateError("Startup approval timed out", "TIMEOUT")
        data = None if body is None else json.dumps(body).encode()
        headers = {"Authorization": f"Bearer {self.token}"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if instance_key:
            headers["Idempotency-Key"] = instance_key
        request = urllib.request.Request(self.url + path, data=data, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=min(self.request_timeout, remaining)) as response:
                if response.status not in (200, 202):
                    raise LockGateError(f"Request rejected (HTTP {response.status})", f"HTTP_{response.status}")
                raw = response.read(16 * 1024 * 1024 + 1)
        except urllib.error.HTTPError as error:
            raise LockGateError(f"Request rejected (HTTP {error.code})", f"HTTP_{error.code}") from None
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise LockGateError("LockGate is unreachable or timed out", "UNREACHABLE") from error
        if len(raw) > 16 * 1024 * 1024:
            raise LockGateError("Server response is too large", "INVALID_RESPONSE")
        try:
            result = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise LockGateError("Server returned invalid JSON", "INVALID_RESPONSE") from error
        if not isinstance(result, dict):
            raise LockGateError("Server returned an invalid response", "INVALID_RESPONSE")
        return result
