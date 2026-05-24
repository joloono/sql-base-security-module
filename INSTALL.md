# INSTALL - Integrating the Security Module into a New Project

Step-by-step guide for copying the `security/` folder into any Express + SQL
project.

## Requirements

The target project should use:

- **Node.js >= 18** for `crypto.timingSafeEqual`, `randomUUID`, and modern
  runtime features.
- **TypeScript >= 5.x** because the module is written in TypeScript.
- **Express 4 or 5**. The middleware signature is compatible with both.
- **SQLite through `better-sqlite3`** for the default store, or a custom
  `SecurityStore` implementation.
- **Zod >= 3.22** for `validateBody`.

## Step 1 - Copy the Folder

```bash
cp -r /path/to/security-module/security /path/to/target-project/server/security
```

The canonical destination is `server/security/`. Other paths work too, but you
must then adjust imports in the target project.

## Step 2 - Install Dependencies

Required:

```bash
npm install zod
npm install better-sqlite3
npm install -D @types/better-sqlite3
```

Express and Express types are expected to already exist in the target project.

If you do not want to use SQLite, omit `better-sqlite3` and implement your own
`SecurityStore` class. See [Security-SQL.md](Security-SQL.md#37-securitystore---pluggable-counter-persistence).

## Step 3 - Add Environment Variables

Create or update `.env`:

```env
# Secret salt for IP hashing. Required in production.
# Generate one with:
#   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
IP_HASH_PEPPER=replace-with-a-long-random-value

# Admin credentials. In production, the module refuses to start when these are
# empty or set to "admin"/"admin".
ADMIN_USER=changeme
ADMIN_PASS=use-a-long-random-passphrase
```

Add local secrets and databases to `.gitignore`:

```gitignore
.env
*.db
*.db-wal
*.db-shm
```

## Step 4 - Create the Security Layer

Create `server/securityLayer.ts`. This file is project-specific wiring and
should not be copied back into the reusable module.

```ts
import Database from "better-sqlite3";
import { createSecurityLayer, SqliteSecurityStore } from "./security";

// SQLite handle. Use either a dedicated database or the main app database.
const sqlite = new Database("data/app.db");
const store = new SqliteSecurityStore(sqlite); // creates its own table

export const security = createSecurityLayer({
  store,
  pepper: process.env.IP_HASH_PEPPER,

  rateLimit: {
    windowMs: 10 * 60_000,
    max: 10,
  },

  abuseGuard: {
    threshold: 5,
    windowMs: 15 * 60_000,
    lockoutSteps: [60_000, 5 * 60_000, 15 * 60_000],
  },

  basicAuth: {
    username: process.env.ADMIN_USER!,
    password: process.env.ADMIN_PASS!,
  },
});
```

## Step 5 - Mount It in Express

In the Express setup file, such as `server/index.ts`:

```ts
import express from "express";
import { security } from "./securityLayer";

const app = express();

app.set("trust proxy", 1);                 // real client IPs behind one proxy
app.use(security.headers);                 // app-wide hardening headers
app.use(express.json({ limit: "64kb" }));  // body size limit
```

## Step 6 - Protect Routes

Write route with full handling:

```ts
import { validateBody } from "./security";
import { security } from "./securityLayer";
import { mySchema } from "./schemas";

app.post(
  "/api/thing",
  security.rateLimit,
  security.abuseGuard.middleware,
  async (req, res) => {
    const r = validateBody(req.body, mySchema);
    if (!r.ok) {
      security.abuseGuard.recordInvalid(req);  // add a strike
      return res.status(400).json({ error: r.errors });
    }
    security.abuseGuard.recordValid(req);      // clear strikes

    // ... process r.data ...
    res.json({ ok: true });
  },
);
```

Admin-protected route:

```ts
app.get("/api/admin/stuff", security.requireAdmin!, async (req, res) => {
  // ... handler ...
});
```

## Step 7 - Smoke Test

```bash
# Valid request - should return 200
curl -X POST http://localhost:3000/api/thing \
  -H 'Content-Type: application/json' \
  -d '{"...": "..."}'

# Invalid request - should return 400 and create a strike
curl -X POST http://localhost:3000/api/thing \
  -H 'Content-Type: application/json' \
  -d '{"broken": true}'

# Admin without auth - should return 401
curl http://localhost:3000/api/admin/stuff

# Admin with auth - should return 200
curl -u $ADMIN_USER:$ADMIN_PASS http://localhost:3000/api/admin/stuff

# 12 quick requests - the last ones should return 429
for i in $(seq 1 12); do
  curl -s -o /dev/null -w '%{http_code}\n' \
    -X POST http://localhost:3000/api/thing \
    -H 'Content-Type: application/json' \
    -d '{"...": "..."}'
done
```

## Step 8 - Go to Production

Deployment checklist:

- [ ] `IP_HASH_PEPPER` is set to a long, random, secret value.
- [ ] `ADMIN_USER` and `ADMIN_PASS` are set and are not `admin`/`admin`.
- [ ] `NODE_ENV=production` is set so weak credential checks are active.
- [ ] The app runs behind HTTPS. If yes, set `headers: { hsts: true }` in
      `securityLayer.ts`.
- [ ] `trust proxy` is set to the correct hop count, usually `1` for one proxy.
- [ ] The database file and `.env` are ignored by git.

## Common Issues

**"Cannot find module 'better-sqlite3'"** - SQLite is not installed or the
target project does not use it. Install `better-sqlite3` or provide a custom
`SecurityStore`.

**Native build errors for `better-sqlite3` on the deployment server** -
`better-sqlite3` is a native module. Run `npm rebuild better-sqlite3` on the
target system or use prebuilt binaries. This is usually acceptable for
single-instance SQLite deployments.

**Rate limiting does not trigger as expected for client IPs** - `trust proxy`
is probably not configured correctly. All requests may appear to come from the
proxy, or `req.ip` may point at the proxy instead of the client. Set
`app.set("trust proxy", 1)` when the app runs behind one trusted proxy.

**Admin login crashes the server during production startup** - This is
intentional. Set strong `ADMIN_USER` and `ADMIN_PASS` values, or pass
`enforceStrongInProduction: false` to `basicAuth` if you explicitly accept the
risk.

**CSP blocks the frontend** - The default CSP works for many single-page app
setups. If the app loads external scripts, analytics, CDN fonts, or similar
assets, allow them explicitly through the `csp` option. See
[Security-SQL.md](Security-SQL.md#34-securityheaders---defense-in-depth-headers).

## What Does Not Belong in the Module Folder

The `security/` directory is intentionally project-agnostic.

Do not copy these files into it:

- `securityLayer.ts`, because it is project-specific configuration.
- App schemas, routes, and business logic.
- Database connection code for the main project.

This keeps the module reusable across projects without modification.
