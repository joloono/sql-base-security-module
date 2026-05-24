# Security Module

Reusable Express + SQL security hardening layer.

This module was originally extracted from an RSVP tracker, but it is now
project-agnostic and ready to copy into any Node.js/Express project with a SQL
database.

## Folder Contents

```text
security-module/
|-- README.md                # this overview
|-- Security-SQL.md          # detailed documentation: what, why, and how
|-- INSTALL.md               # step-by-step integration guide
|-- AUDIT.md                 # repository audit and internationalization notes
|-- package-requirements.txt # npm dependencies required by the module
`-- security/                # the reusable module to copy into projects
    |-- index.ts             # entry point and createSecurityLayer factory
    |-- store.ts             # SecurityStore interface, SQLite and memory stores
    |-- rateLimit.ts         # sliding-window volume cap
    |-- abuseGuard.ts        # escalating lockout for invalid input
    |-- basicAuth.ts         # constant-time HTTP Basic Auth
    |-- securityHeaders.ts   # CSP and security headers
    |-- validate.ts          # Zod validation and payload-size helper
    |-- ipUtils.ts           # trust-proxy-aware IP handling and peppered SHA-256
    `-- README.md            # in-module quick reference
```

## Quick Start

1. Copy the `security/` folder into the target project, for example
   `server/security/`.
2. Install dependencies:
   `npm install zod better-sqlite3` and
   `npm install -D @types/better-sqlite3`.
3. Create a `.env` file with `IP_HASH_PEPPER`, `ADMIN_USER`, and `ADMIN_PASS`.
4. Call `createSecurityLayer({...})` and mount the middleware in Express.
5. Run the smoke tests from [INSTALL.md](INSTALL.md).

## What It Provides

- Per-IP, per-route rate limiting with a sliding window and generous defaults.
- Escalating lockout for repeated invalid input.
- Constant-time Basic Auth for admin endpoints.
- Secure HTTP headers: CSP, frameguard, nosniff, and related policies.
- Zod validation with a 64 KB payload cap.
- Peppered IP hashing for privacy by design.
- Pluggable counter storage: SQLite by default, Redis/Postgres possible.

Design principle: **secure without blocking legitimate users**. Strikes are
earned only by bad traffic, never by a valid first submission.

For the full reasoning behind each security practice, see
[Security-SQL.md](Security-SQL.md).
