# Sicherheitsmodul

Wiederverwendbares Express + SQL Security-Hardening-Layer.
Ursprünglich extrahiert aus dem RSVP-Tracker, projekt-unabhängig
und ready zum Droppen in beliebige Node.js/Express-Projekte mit SQL-DB.

## Inhalt dieses Ordners

```
Sicherheitsmodul/
├── README.md                ← dieses File: Übersicht
├── Security-SQL.md          ← ausführliche Doku (was, warum, wie)
├── INSTALL.md               ← Schritt-für-Schritt-Anleitung zum Einbau
├── package-requirements.txt ← npm-Dependencies, die das Modul braucht
└── security/                ← DAS MODUL — diesen Ordner kopierst du
    ├── index.ts             ← Einstiegspunkt + createSecurityLayer-Factory
    ├── store.ts             ← SecurityStore-Interface, SQLite- & Memory-Impls
    ├── rateLimit.ts         ← Sliding-Window Volumen-Cap
    ├── abuseGuard.ts        ← Eskalierender Lockout bei ungültiger Eingabe
    ├── basicAuth.ts         ← Constant-time HTTP Basic Auth
    ├── securityHeaders.ts   ← CSP + sichere Header
    ├── validate.ts          ← Zod + Größenlimit-Helper
    ├── ipUtils.ts           ← Trust-Proxy-IP + gepfefferter SHA-256
    └── README.md            ← In-Modul Quick-Reference
```

## Schnellstart

1. `security/`-Ordner ins neue Projekt kopieren → `server/security/`
2. `npm install zod better-sqlite3` + `npm install -D @types/better-sqlite3`
3. `.env` anlegen mit `IP_HASH_PEPPER`, `ADMIN_USER`, `ADMIN_PASS`
4. `createSecurityLayer({...})` aufrufen und Middleware in Express einhängen
5. Smoke-Test laufen lassen

Vollständige Anleitung: siehe **INSTALL.md**.

## Was es leistet

- Rate-Limit pro IP pro Route (Sliding Window, großzügige Defaults)
- Lockout bei wiederholt ungültiger Eingabe (eskalierend, selbstheilend)
- Constant-time Basic Auth für Admin-Endpoints
- Sichere HTTP-Header (CSP, frameguard, nosniff, ...)
- Zod-Validierung + 64 KB Payload-Cap
- Gepfeffertes IP-Hashing (Privacy-by-design)
- Austauschbarer Counter-Store (SQLite default, Redis/Postgres möglich)

Designprinzip: **sicher, ohne der Usability im Weg zu stehen** —
Strikes werden ausschließlich durch *schlechten* Traffic verdient,
nie durch valide Erstabsender.

Vollständige Begründung jeder Best Practice: siehe **Security-SQL.md**.
