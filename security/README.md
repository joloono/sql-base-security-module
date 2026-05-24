# `security/` - reusable SQL-app hardening layer

A self-contained, project-agnostic Express security layer. Copy the whole
`security/` folder into any Express + SQL project. No project-specific code
lives here. No external dependencies beyond Node core + Express types - the
SQLite store only needs a `better-sqlite3`-compatible handle, passed in.

**Design principle:** secure without hurting usability. Volume limits are
loose, lockouts trigger **only on invalid/abusive input** (never on a valid
submission), cooldowns are minutes not hours, and a single valid request
clears an IP's strike record.

## Quick start

```ts
import Database from "better-sqlite3";
import { createSecurityLayer, SqliteSecurityStore } from "./security";

const sqlite = new Database("data/app.db");
const store = new SqliteSecurityStore(sqlite); // creates its own table

const security = createSecurityLayer({
  store,
  pepper: process.env.IP_HASH_PEPPER,
  rateLimit: { windowMs: 10 * 60_000, max: 10 },
  abuseGuard: { threshold: 5, windowMs: 15 * 60_000 },
  basicAuth: {
    username: process.env.ADMIN_USER!,
    password: process.env.ADMIN_PASS!,
  },
});

app.set("trust proxy", 1);     // required behind a proxy for real client IPs
app.use(security.headers);     // app-wide hardening headers

// Protect a write endpoint:
app.post(
  "/api/thing",
  security.rateLimit,
  security.abuseGuard.middleware,
  (req, res) => {
    const result = validateBody(req.body, mySchema);
    if (!result.ok) {
      security.abuseGuard.recordInvalid(req); // strike: bad input
      return res.status(400).json({ error: result.errors });
    }
    security.abuseGuard.recordValid(req);     // clear strikes: good actor
    // ... persist result.data ...
  },
);

// Protect admin endpoints:
app.get("/api/admin/x", security.requireAdmin!, handler);
```

## Components & options

| Component | Purpose | Key options (defaults) |
|---|---|---|
| `rateLimit` | Sliding-window volume cap per IP per route | `windowMs` (10 min), `max` (10), `bucket` (method+path) |
| `createAbuseGuard` | Escalating lockout on invalid input only | `threshold` (5), `windowMs` (15 min), `lockoutSteps` ([1m,5m,15m]) |
| `basicAuth` | Constant-time HTTP Basic auth | `username`, `password`, `enforceStrongInProduction` (true) |
| `securityHeaders` | Safe headers that don't break a SPA | `hsts` (false), `csp` (SPA-permissive default) |
| `validateBody` | Zod validation + payload size cap | `maxBytes` (64 KB) |
| `SecurityStore` | Pluggable counter storage | `SqliteSecurityStore`, `MemorySecurityStore` |

## Swapping the backing store

The middleware never touches a DB directly - it talks to the `SecurityStore`
interface (`hit` / `count` / `reset` / `prune`). Ship with
`SqliteSecurityStore` today; later implement the same 4 methods against
Postgres or Redis and pass that instead. Nothing else changes.

## Environment variables

| Var | Purpose |
|---|---|
| `IP_HASH_PEPPER` | Secret salt so stored IP hashes can't be rainbow-tabled. **Set in production.** |
| `ADMIN_USER` / `ADMIN_PASS` | Admin basic-auth credentials. App refuses to start with weak/default creds when `NODE_ENV=production`. |

## Notes / limits

- `SqliteSecurityStore` is single-process (matches SQLite). Behind a load
  balancer, implement `SecurityStore` against Redis instead.
- HSTS is off by default - only enable on all-HTTPS deployments (it's sticky).
- The default CSP allows `'unsafe-inline'` styles for SPA toolchains. Tighten
  via the `csp` option if your build supports nonces/hashes.
