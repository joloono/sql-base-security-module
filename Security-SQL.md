# `security/` - Module Documentation

A drop-in, project-agnostic Express + SQL security layer.

The `security/` folder contains no project-specific code. One
`createSecurityLayer()` call wires everything together.

Design principle: **secure without blocking legitimate users**. Limits penalize
bad traffic, never honest first submissions.

---

## 1. What It Does

| Concern | Component | Default behavior |
|---|---|---|
| Too many requests from one IP | `rateLimit` | 10 requests / 10 min per IP per route, then HTTP 429 |
| Repeated invalid or abusive payloads | `abuseGuard` | 5 strikes / 15 min, then escalating cooldowns: 1m, 5m, 15m |
| Brute force against admin login | `basicAuth` | Constant-time comparison and weak-credential rejection in production |
| XSS, clickjacking, MIME sniffing | `securityHeaders` | CSP, frameguard, nosniff, referrer policy, permissions policy |
| Invalid or oversized payloads | `validateBody` | Zod schema validation plus a 64 KB byte cap |
| IP correlation and privacy | `hashIp` | Peppered SHA-256 hash, not reversible through rainbow tables |
| Counter persistence | `SecurityStore` | Pluggable interface: SQLite today, Postgres/Redis later |

---

## 2. Architecture

```text
Request
  |
  v
+--------------------------------+
| securityHeaders, app-wide      |
+---------------+----------------+
                |
                v
+---------------------------------------------+
| Write routes                                 |
| - rateLimit: volume cap                      |
| - abuseGuard.middleware: current lockout     |
+---------------+-----------------------------+
                |
                v
+---------------------------------------------+
| validateBody(req.body, schema)               |
| - invalid: recordInvalid, add a strike       |
| - valid: recordValid, clear strikes          |
+---------------+-----------------------------+
                |
                v
Business logic

Counters for rateLimit and abuseGuard live in a SecurityStore:

+----------------------+--------------------------------------------+
| SqliteSecurityStore  | shares the app DB, table security_events   |
| MemorySecurityStore  | test/dev fallback                         |
| Custom store         | Postgres, Redis, or another backend       |
+----------------------+--------------------------------------------+
```

All middleware is synchronous and free of `await`, so counter checks and
increments do not introduce asynchronous race conditions.

---

## 3. Components

### 3.1 `rateLimit` - Sliding-Window Volume Cap

**What it does:** Limits how many requests one IP can send to one route during
a time window. It returns HTTP 429 and `Retry-After` when the limit is exceeded.

**Best practices:**

- **Sliding window instead of fixed bucket:** avoids traffic spikes at window
  boundaries.
- **Key = route plus peppered IP hash:** each endpoint gets its own bucket, so
  heavy traffic to one endpoint does not block another endpoint.
- **Standard headers:** sends `RateLimit-Limit`, `RateLimit-Remaining`, and
  `Retry-After` so clients can throttle themselves.
- **Generous defaults:** 10 requests per 10 minutes is intended to avoid
  blocking real users who retry a form a few times. Stricter limits are opt-in
  per route.

**Options:** `windowMs` (10 min), `max` (10), `bucket` (method + path),
`pepper`, `message`.

### 3.2 `abuseGuard` - Lockout for Invalid Input

**What it does:** Tracks only failed or invalid attempts per IP and applies an
escalating cooldown after the strike threshold is exceeded.

**Best practices:**

- **Penalizes bad signals, not volume:** strikes are added only by
  `recordInvalid()` after failed Zod parsing, garbage payloads, auth brute
  force, or similar invalid input. Valid requests never add strikes.
- **Self-healing:** `recordValid()` clears the strike record. A user who fixes
  an input error can continue immediately.
- **Progressive lockout:** 1 min, then 5 min, then 15 min. This is long enough
  to slow scripts but short enough for a confused legitimate user to wait out.
- **Per-route bucketing:** invalid input on one endpoint does not block another
  endpoint.
- **Same counter path as `rateLimit`:** both use the same `SecurityStore`
  abstraction.

**Options:** `threshold` (5), `windowMs` (15 min), `lockoutSteps`
(`[1m, 5m, 15m]`), `bucket`, `pepper`, `message`.

### 3.3 `basicAuth` - Credential Checks

**What it does:** Provides HTTP Basic Auth middleware for admin endpoints.

**Best practices:**

- **Constant-time comparison:** uses `crypto.timingSafeEqual` to reduce timing
  attack exposure compared with naive `===` checks.
- **Length-aware checks:** credentials with different lengths still go through
  a comparison path before failing.
- **Production guardrail:** throws during startup if credentials are empty or
  `admin`/`admin` while `NODE_ENV=production`.
- **Same evaluation shape for wrong user and wrong password:** both `okUser`
  and `okPass` are evaluated before the middleware decides whether to reject.
- **Standard 401 with `WWW-Authenticate`:** browsers and HTTP clients know how
  to prompt correctly.

**Options:** `username`, `password`, `realm` (`Admin`),
`enforceStrongInProduction` (true).

### 3.4 `securityHeaders` - Defense-in-Depth Headers

**What it does:** Sets a curated app-wide set of HTTP security headers.

**Best practices:**

- **Content-Security-Policy:** the default is SPA-compatible:
  `default-src 'self'`, same-origin scripts, no objects, no framed ancestors,
  and `base-uri 'self'`. Pass the `csp` option to tighten it for builds that
  support nonces or hashes.
- **X-Frame-Options plus CSP frame-ancestors:** clickjacking is blocked on two
  layers.
- **X-Content-Type-Options: nosniff:** blocks MIME-sniffing attacks.
- **Referrer-Policy: strict-origin-when-cross-origin:** avoids leaking full
  URLs to cross-origin destinations.
- **Permissions-Policy:** disables geolocation, microphone, and camera by
  default.
- **X-XSS-Protection: 0:** disables the legacy IE/old-Chrome filter, which has
  caused vulnerabilities. CSP is the modern protection.
- **HSTS is opt-in:** it is sticky in browsers, so it is not enabled by default
  for deployments that may still serve HTTP.

### 3.5 `validateBody` - Schema and Size Checks

**What it does:** Runs a Zod schema against a request body and enforces a hard
byte cap. It returns a result object.

**Best practices:**

- **Schema-driven validation everywhere:** never trust client input; write
  endpoints should pass through Zod.
- **Payload size limit:** the 64 KB default helps protect against memory
  amplification before schema validation runs.
- **No exceptions across middleware boundaries:** returns
  `{ ok, data, errors, rejected }`, so the caller controls the HTTP response
  shape and can call `recordInvalid()`.
- **`rejected` versus `!ok`:** separates "could not even be parsed or accepted"
  from "valid JSON that failed the schema". Both can still be treated as
  strikes.

### 3.6 `ipUtils` - IP Resolution and Hashing

**What it does:** Resolves the real client IP and hashes it before storage.

**Best practices:**

- **Trust-proxy aware:** uses `req.ip`, which respects Express `trust proxy`,
  and falls back to the socket address. This avoids trusting spoofable headers
  when no proxy is configured.
- **Peppered hashing:** stores `SHA-256("<server-secret>:<ip>")`. The IPv4
  space is small enough for unpeppered hashes to be brute-forced quickly, so
  the pepper is what makes stored hashes non-reversible in practice.
- **Environment configuration:** use `IP_HASH_PEPPER`. A marked dev default
  exists so local development still runs, but production should always provide
  a secret value.

### 3.7 `SecurityStore` - Pluggable Counter Persistence

**What it does:** Defines the only storage contract the middleware knows about.
It has four methods: `hit`, `count`, `reset`, and `prune`.

**Best practices:**

- **Persistent by default:** `SqliteSecurityStore` keeps counters across
  process restarts, so restarting the app does not create a free abuse window.
- **Indexed queries:** `(key, ts)` index on `security_events` keeps `count`
  efficient.
- **Throttled pruning:** `prune()` runs at most once per minute regardless of
  request rate.
- **Auto-bootstrap:** creates its table and index on first use, so no separate
  migration step is needed.
- **Interface-based design:** replace SQLite with Redis or Postgres without
  changing the middleware.

---

## 4. Usable Security Principles

These design choices distinguish this layer from a generic
`helmet + express-rate-limit` setup:

1. **Strikes are earned, not assumed.** Volume alone never triggers a lockout;
   only `recordInvalid()` does. A real user who sends valid data is invisible
   to `abuseGuard`.
2. **Validation is the abuse signal.** A Zod failure is a clean signal that the
   request was not acceptable. It feeds directly into lockout tracking.
3. **Success restores goodwill.** A valid request clears the strike record.
4. **Cooldowns are minutes, not hours.** They slow scripted abuse without
   creating long accidental lockouts.
5. **Buckets are per route.** A noisy endpoint does not affect other endpoints.
6. **Production guardrails fail loudly.** Weak admin credentials in production
   crash startup instead of silently shipping.
7. **Headers are chosen so normal SPAs still work.** No `'unsafe-eval'`; inline
   styles are allowed by default and can be tightened with options.
8. **No `await` in security middleware.** Synchronous SQLite and synchronous
   counters avoid time-of-check/time-of-use races between check and increment.

---

## 5. Covered and Out-of-Scope Threats

### Covered

- Volume abuse and form spam through `rateLimit`.
- Targeted brute force against inputs or login through `abuseGuard` and
  timing-safe `basicAuth`.
- Invalid or oversized payloads through `validateBody` and
  `express.json({ limit })`.
- Clickjacking through `X-Frame-Options` and `frame-ancestors`.
- MIME sniffing through `X-Content-Type-Options`.
- Script injection risk reduction through CSP, within the limits of allowing
  inline styles.
- Referrer leakage through `Referrer-Policy`.
- Rainbow-table reversal of stored IP hashes through peppered hashing.
- Default credentials in production through startup refusal.
- Counter resets on restart through persistent `SecurityStore`.

### Not Covered by Design

- **Bot detection or CAPTCHA:** handle this at another layer with hCaptcha,
  Turnstile, or equivalent if needed.
- **Network-level DDoS:** belongs at CDN/WAF/proxy level.
- **Session management or CSRF:** Basic Auth does not need CSRF protection, but
  cookie-based sessions should add CSRF middleware.
- **Database-level SQL injection:** handle this outside the module with
  parameterized queries or an ORM/query builder.
- **Distributed counters across multiple nodes:** `SqliteSecurityStore` is
  single-process. Use a Redis-backed `SecurityStore` behind a load balancer.

---

## 6. Configuration Surface

```ts
createSecurityLayer({
  store,                       // SecurityStore: SQLite, memory, or custom
  pepper: process.env.IP_HASH_PEPPER,

  rateLimit:  { windowMs, max, bucket, message },
  abuseGuard: { threshold, windowMs, lockoutSteps, bucket, message },
  basicAuth:  { username, password, realm, enforceStrongInProduction },
  headers:    { csp, hsts },
});
```

Every component can also be imported individually when finer control is needed.

### Environment Variables

| Variable | Purpose | Required? |
|---|---|---|
| `IP_HASH_PEPPER` | Secret salt for IP hashing | **Yes in production** |
| `ADMIN_USER` / `ADMIN_PASS` | Basic Auth credentials | **Yes in production** |

---

## 7. Canonical Wiring Pattern

```ts
app.set("trust proxy", 1);          // real client IPs behind one proxy
app.use(security.headers);          // app-wide hardening headers
app.use(express.json({ limit: "64kb" })); // body cap

app.post(
  "/api/thing",
  security.rateLimit,               // volume cap
  security.abuseGuard.middleware,   // blocks if currently locked out
  (req, res) => {
    const r = validateBody(req.body, mySchema);
    if (!r.ok) {
      security.abuseGuard.recordInvalid(req); // add strike
      return res.status(400).json({ error: r.errors });
    }
    security.abuseGuard.recordValid(req);     // clear strikes
    // ... persist r.data ...
  },
);

app.get("/api/admin/x", security.requireAdmin!, handler);
```

This order is the backbone of the module:

```text
volume cap -> lockout check -> validate -> record outcome
```

---

## 8. Files

```text
security/
|-- index.ts             # entry point and createSecurityLayer factory
|-- store.ts             # SecurityStore interface, SQLite and memory stores
|-- rateLimit.ts         # sliding-window volume cap
|-- abuseGuard.ts        # escalating lockout for invalid input
|-- basicAuth.ts         # constant-time HTTP Basic Auth
|-- securityHeaders.ts   # CSP and secure headers
|-- validate.ts          # Zod validation and size cap helper
|-- ipUtils.ts           # trust-proxy IP handling and peppered SHA-256
`-- README.md            # copy-paste setup and options table
```

Copy the complete `security/` folder into another Express + SQL project, pass a
`SqliteSecurityStore(yourDb)` or another `SecurityStore` to
`createSecurityLayer(...)`, and the same protections are available there.
