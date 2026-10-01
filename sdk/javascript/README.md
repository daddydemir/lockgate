# lockgate-client

Dependency-free Node.js client for [LockGate](https://github.com/daddydemir/lockgate). Requires Node.js 18 or newer.

```sh
npm install lockgate-client
```

```js
import { LockGateClient } from "lockgate-client";

const client = new LockGateClient({
  url: process.env.LOCKGATE_URL,
  token: process.env.LOCKGATE_TOKEN,
});

const controller = new AbortController();
const deadline = setTimeout(() => controller.abort(), 10 * 60 * 1000);
try {
  const config = await client.getConfig({ signal: controller.signal });
  const dbPassword = config.DB_PASSWORD;
} finally {
  clearTimeout(deadline);
}
```

The client waits for human approval, follows the server polling interval, blocks redirects, and fails closed on denial, timeout, network errors, or invalid responses. It never writes secrets to disk or environment variables.
