import { randomUUID } from "node:crypto";

export class LockGateError extends Error {
  constructor(message, code = "LOCKGATE_ERROR") {
    super(message);
    this.name = "LockGateError";
    this.code = code;
  }
}

export class LockGateClient {
  constructor({ url, token, pollInterval = 3000, requestTimeout = 15000 }) {
    const origin = new URL(url);
    if (!["http:", "https:"].includes(origin.protocol) || origin.username || origin.password || origin.pathname !== "/" || origin.search || origin.hash) {
      throw new LockGateError("LOCKGATE_URL must be an HTTP(S) origin", "CONFIG");
    }
    if (!token) throw new LockGateError("LOCKGATE_TOKEN is required", "CONFIG");
    this.url = origin.origin;
    this.token = token;
    this.pollInterval = Math.max(pollInterval, 3000);
    this.requestTimeout = requestTimeout;
  }

  async getConfig({ signal } = {}) {
    const instanceKey = randomUUID();
    let access = await this.#request("POST", "/api/v1/access", {}, instanceKey, signal);
    for (;;) {
      switch (access.status) {
        case "approved": {
          const bundles = Object.values(access.secrets ?? {});
          if (bundles.length !== 1) throw new LockGateError("Expected exactly one configured secret bundle", "INVALID_RESPONSE");
          return bundles[0];
        }
        case "denied":
          throw new LockGateError("Access denied by administrator", "DENIED");
        case "revoked":
          access = await this.#request("POST", "/api/v1/access", {}, instanceKey, signal);
          break;
        case "waiting_approval": {
          if (typeof access.request_id !== "string" || !/^[A-Za-z0-9_-]+$/.test(access.request_id)) {
            throw new LockGateError("Server returned an invalid request ID", "INVALID_RESPONSE");
          }
          const advised = Number.isFinite(access.retry_after) ? access.retry_after * 1000 : 0;
          await sleep(Math.max(this.pollInterval, advised), signal);
          access = await this.#request("GET", `/api/v1/access/${encodeURIComponent(access.request_id)}`, undefined, undefined, signal);
          break;
        }
        default:
          throw new LockGateError(`Unexpected access status: ${String(access.status)}`, "INVALID_RESPONSE");
      }
    }
  }

  async #request(method, path, body, instanceKey, outerSignal) {
    const controller = new AbortController();
    const abort = () => controller.abort(outerSignal?.reason);
    if (outerSignal?.aborted) abort();
    else outerSignal?.addEventListener("abort", abort, { once: true });
    const timer = setTimeout(() => controller.abort(), this.requestTimeout);
    try {
      const response = await fetch(this.url + path, {
        method,
        redirect: "error",
        signal: controller.signal,
        headers: {
          Authorization: `Bearer ${this.token}`,
          ...(body === undefined ? {} : { "Content-Type": "application/json" }),
          ...(instanceKey ? { "Idempotency-Key": instanceKey } : {}),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      if (![200, 202].includes(response.status)) {
        throw new LockGateError(`Request rejected (HTTP ${response.status})`, `HTTP_${response.status}`);
      }
      const length = Number(response.headers.get("content-length") ?? 0);
      if (length > 16 * 1024 * 1024) throw new LockGateError("Server response is too large", "INVALID_RESPONSE");
      const text = await response.text();
      if (new TextEncoder().encode(text).length > 16 * 1024 * 1024) throw new LockGateError("Server response is too large", "INVALID_RESPONSE");
      try { return JSON.parse(text); }
      catch { throw new LockGateError("Server returned invalid JSON", "INVALID_RESPONSE"); }
    } catch (error) {
      if (error instanceof LockGateError) throw error;
      if (outerSignal?.aborted) throw outerSignal.reason ?? new LockGateError("Startup cancelled", "CANCELLED");
      if (controller.signal.aborted) throw new LockGateError("LockGate request timed out", "TIMEOUT");
      throw new LockGateError("LockGate is unreachable", "UNREACHABLE");
    } finally {
      clearTimeout(timer);
      outerSignal?.removeEventListener("abort", abort);
    }
  }
}

function sleep(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(signal.reason ?? new LockGateError("Startup cancelled", "CANCELLED"));
    const abort = () => {
      clearTimeout(timer);
      reject(signal.reason ?? new LockGateError("Startup cancelled", "CANCELLED"));
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", abort);
      resolve();
    }, ms);
    signal?.addEventListener("abort", abort, { once: true });
  });
}
