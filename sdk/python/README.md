# lockgate-client

Standard-library-only Python client for [LockGate](https://github.com/daddydemir/lockgate). Requires Python 3.10 or newer.

```sh
pip install lockgate-client
```

```python
import os
from lockgate_client import LockGateClient

client = LockGateClient(
    url=os.environ["LOCKGATE_URL"],
    token=os.environ["LOCKGATE_TOKEN"],
)
config = client.get_config(startup_timeout=600)
db_password = config["DB_PASSWORD"]
```

The client waits for human approval, follows the server polling interval, blocks redirects, and fails closed on denial, timeout, network errors, or invalid responses. It never writes secrets to disk or environment variables.
