# INSTALL — Sicherheitsmodul in ein neues Projekt einbauen

Schritt-für-Schritt-Anleitung, wie du den `security/`-Ordner in ein beliebiges
Express + SQL-Projekt droppst.

## Voraussetzungen

Dein Zielprojekt nutzt:
- **Node.js ≥ 18** (für `crypto.timingSafeEqual`, `randomUUID` etc.)
- **TypeScript ≥ 5.x** (Modul ist in TS geschrieben)
- **Express 4 oder 5** (Middleware-Signatur identisch)
- **SQLite via `better-sqlite3`** (für den Default-Store; sonst eigenen `SecurityStore` implementieren)
- **Zod ≥ 3.22** (für `validateBody`)

## Schritt 1 — Ordner kopieren

```bash
cp -r /pfad/zu/Sicherheitsmodul/security  /pfad/zum/Zielprojekt/server/security
```

Genau so: in `server/security/`. Andere Pfade gehen auch — passe dann
die Imports im Zielprojekt entsprechend an.

## Schritt 2 — Dependencies installieren

Pflicht:

```bash
npm install zod
npm install better-sqlite3
npm install -D @types/better-sqlite3
```

(Express und Express-Types sollten in deinem Projekt schon drin sein.)

Wenn du SQLite *nicht* nutzen willst, kannst du `better-sqlite3` weglassen
und implementierst eigene `SecurityStore`-Klasse — siehe `Security-SQL.md` §3.7.

## Schritt 3 — Environment-Variablen anlegen

In `.env`:

```env
# Geheimes Salt für IP-Hashing (in Production PFLICHT).
# Generieren mit:
#   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
IP_HASH_PEPPER=ersetze-mit-langem-zufallswert

# Admin-Credentials. Das Modul WEIGERT SICH zu starten, wenn diese in
# Production leer oder "admin"/"admin" sind.
ADMIN_USER=changeme
ADMIN_PASS=verwende-eine-lange-zufaellige-passphrase
```

In `.gitignore`:

```
.env
*.db
*.db-wal
*.db-shm
```

## Schritt 4 — Security-Layer instanziieren

Erstelle `server/securityLayer.ts` (projektspezifische Verdrahtung,
gehört NICHT ins wiederverwendbare Modul):

```ts
import Database from "better-sqlite3";
import { createSecurityLayer, SqliteSecurityStore } from "./security";

// SQLite-Handle — entweder eigene DB oder die deines Hauptprojekts
const sqlite = new Database("data/app.db");
const store = new SqliteSecurityStore(sqlite); // legt eigene Tabelle an

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

## Schritt 5 — In Express einhängen

In deinem Express-Setup (`server/index.ts` oder wie es bei dir heißt):

```ts
import express from "express";
import { security } from "./securityLayer";

const app = express();

app.set("trust proxy", 1);            // echte Client-IPs hinter Proxy
app.use(security.headers);            // app-weite Hardening-Header
app.use(express.json({ limit: "64kb" }));  // Body-Größenlimit
```

## Schritt 6 — Routen schützen

Write-Route mit voller Behandlung:

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
      security.abuseGuard.recordInvalid(req);  // Strike geben
      return res.status(400).json({ error: r.errors });
    }
    security.abuseGuard.recordValid(req);      // Strikes löschen

    // ... r.data verarbeiten ...
    res.json({ ok: true });
  },
);
```

Admin-geschützte Route:

```ts
app.get("/api/admin/stuff", security.requireAdmin!, async (req, res) => {
  // ... handler ...
});
```

## Schritt 7 — Smoke-Test

```bash
# Valider Request — sollte 200 sein
curl -X POST http://localhost:3000/api/thing \
  -H 'Content-Type: application/json' \
  -d '{"...": "..."}'

# Invalider Request — sollte 400 sein und einen Strike erzeugen
curl -X POST http://localhost:3000/api/thing \
  -H 'Content-Type: application/json' \
  -d '{"broken": true}'

# Admin ohne Auth — sollte 401 sein
curl http://localhost:3000/api/admin/stuff

# Admin mit Auth — sollte 200 sein
curl -u $ADMIN_USER:$ADMIN_PASS http://localhost:3000/api/admin/stuff

# 12 schnelle Requests — die letzten sollten 429 sein
for i in $(seq 1 12); do
  curl -s -o /dev/null -w '%{http_code}\n' \
    -X POST http://localhost:3000/api/thing \
    -H 'Content-Type: application/json' \
    -d '{"...": "..."}'
done
```

## Schritt 8 — In Production gehen

Checkliste vor dem Deploy:

- [ ] `IP_HASH_PEPPER` gesetzt (lang, zufällig, geheim)
- [ ] `ADMIN_USER` / `ADMIN_PASS` gesetzt (nicht "admin"/"admin")
- [ ] `NODE_ENV=production` gesetzt (aktiviert die Cred-Verweigerung)
- [ ] App läuft hinter HTTPS — wenn ja, in `securityLayer.ts` setzen:
      `headers: { hsts: true }`
- [ ] `trust proxy` auf die richtige Anzahl Hops gesetzt (1 für einen Proxy)
- [ ] DB-Datei und `.env` im `.gitignore`

## Häufige Stolpersteine

**"Cannot find module 'better-sqlite3'"** — Du nutzt SQLite nicht oder
hast es nicht installiert. Entweder installieren oder eigenen
`SecurityStore` implementieren.

**Native-Build-Fehler bei `better-sqlite3` auf Deploy-Server** —
`better-sqlite3` ist ein Native-Modul. Auf dem Zielsystem muss
`npm rebuild better-sqlite3` laufen, oder du nutzt prebuilt binaries.
Für Single-Instance-Deployments (typisch SQLite) ist das in Ordnung.

**Rate-Limit triggert nicht, obwohl die IP gleich ist** — Trust-Proxy
ist nicht gesetzt; alle Requests kommen vom Proxy mit derselben IP, oder
`req.ip` zeigt auf den Proxy statt den Client. Lösung: `app.set("trust proxy", 1)`.

**Admin-Login crasht den Server beim Start in Production** — Beabsichtigt.
Setze starke `ADMIN_USER`/`ADMIN_PASS` oder nimm das `enforceStrongInProduction: false`
in `basicAuth` rein (nicht empfohlen).

**CSP blockiert dein Frontend** — Default-CSP ist SPA-tauglich, aber wenn
du externe Scripts (Analytics, CDN-Fonts etc.) lädst, musst du sie in der
`csp`-Option explizit erlauben. Beispiel siehe `Security-SQL.md` §3.4.

## Was NICHT in den Modul-Ordner gehört

Das `security/`-Verzeichnis ist absichtlich projekt-unabhängig.
**Nicht hineinkopieren:**
- `securityLayer.ts` (projektspezifische Konfiguration — bleibt in `server/`)
- App-Schemas, Routen, Business-Logik
- DB-Connection-Code des Hauptprojekts

So bleibt das Modul beim nächsten Projekt 1:1 kopierbar.
