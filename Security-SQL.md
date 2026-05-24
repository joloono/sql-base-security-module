# `security/` — Modul-Dokumentation

Ein drop-in, projekt-unabhängiges Express + SQL Security-Layer.
Null projekt-spezifischer Code im Ordner; ein einziger `createSecurityLayer()`-Aufruf verdrahtet alles.
Designprinzip: **"sicher, ohne der Usability im Weg zu stehen"** — Limits bestrafen *schlechten* Traffic, niemals ehrliche Erstabsender.

---

## 1. Was es tut (Überblick)

| Anliegen | Komponente | Default-Verhalten |
|---|---|---|
| Zu viele Requests von einer IP | `rateLimit` | 10 Requests / 10 min pro IP pro Route → 429 |
| Wiederholte ungültige/missbräuchliche Payloads | `abuseGuard` | 5 Strikes / 15 min → eskalierender Cooldown (1m → 5m → 15m) |
| Brute-Force auf Admin-Login | `basicAuth` | Constant-time-Vergleich, lehnt schwache Creds in Production ab |
| XSS / Clickjacking / MIME-Sniffing | `securityHeaders` | CSP, frameguard, nosniff, referrer policy, permissions policy |
| Müll-/Überdimensionierte Payloads | `validateBody` | Zod-Schema + 64 KB Byte-Cap |
| IP-Korrelation / Privacy | `hashIp` | Gepfefferter SHA-256-Hash (nicht via Rainbow-Table reversibel) |
| Zähler-Persistenz | `SecurityStore` | Austauschbar: SQLite heute, Postgres/Redis morgen — gleiches Interface |

---

## 2. Architektur

```
                 ┌──────────────────────────────┐
   Request ──►   │  securityHeaders (app-weit)  │
                 └──────────────┬───────────────┘
                                ▼
            ┌──────────────────────────────────────────┐
   auf      │  rateLimit          ← Volumen-Cap        │
   Write-   │  abuseGuard.middleware  ← Sperre, falls   │
   Routen:  │                            aktuell        │
            │                            blockiert       │
            └──────────────┬───────────────────────────┘
                           ▼
            ┌──────────────────────────────────────────┐
            │  validateBody(req.body, schema)          │
            │    invalid? → recordInvalid (Strike)     │
            │    valid?   → recordValid   (Strikes weg)│
            └──────────────┬───────────────────────────┘
                           ▼
                       Business-Logik

   Zähler für rateLimit + abuseGuard leben in einem SecurityStore:
   ┌──────────────────────┐
   │ SqliteSecurityStore  │  teilt sich die App-DB, Tabelle `security_events`
   │ MemorySecurityStore  │  Test/Dev-Fallback
   │ <deine Impl>         │  Postgres / Redis / etc.
   └──────────────────────┘
```

Sämtliche Middleware ist synchron und frei von `await` — keine Race-Conditions auf den Zählern.

---

## 3. Komponenten im Detail

### 3.1 `rateLimit` — Sliding-Window Volumen-Cap

**Was:** Begrenzt, wie viele Requests eine einzelne IP an eine bestimmte Route innerhalb eines Zeitfensters senden darf. Liefert HTTP 429 + `Retry-After` bei Überschreitung.

**Best Practices:**
- **Sliding Window** (kein Fixed Bucket) — keine Traffic-Spikes an den Fenster-Grenzen.
- **Schlüssel = (Route × gepfefferter IP-Hash)** — separate Buckets pro Endpoint; ein lauter Endpoint sperrt keinen anderen.
- **Standard-Header** — sendet `RateLimit-Limit`, `RateLimit-Remaining`, `Retry-After`, damit Clients sich selbst drosseln können.
- **Großzügige Defaults** (10 / 10 min) — so gewählt, dass eine echte Familie, die ein Formular ausfüllt und zweimal retries, *nie* dagegen läuft. Schärfere Limits sind opt-in pro Route.

**Optionen:** `windowMs` (10 min), `max` (10), `bucket` (method+path), `pepper`, `message`.

### 3.2 `abuseGuard` — Lockout bei ungültiger Eingabe

**Was:** Trackt **ausschließlich fehlgeschlagene/ungültige Versuche** pro IP und verhängt einen eskalierenden Cooldown, sobald eine Schwelle überschritten ist.

**Best Practices:**
- **Bestraft schlechte Signale, nicht Volumen** — Strikes werden ausschließlich von `recordInvalid()` hinzugefügt (gescheitertes Zod-Parsen, Müll-Body, Auth-Brute-Force), niemals durch valide Requests. Das ist das zentrale Usability-Prinzip.
- **Selbstheilend** — `recordValid()` löscht den Strike-Record. Ein User, der seinen Fehler korrigiert, hat sofort wieder eine weiße Weste.
- **Progressiver Lockout** — 1 min → 5 min → 15 min. Lang genug, um Skript-Abuse abzuwehren; kurz genug, dass ein verwirrter ehrlicher User es aussitzen kann.
- **Per-Route-Bucketing** — wie bei `rateLimit`: Fehler an einem Endpoint sperren keinen anderen.
- **Gleicher constant-time-Datenpfad** wie `rateLimit` — nutzt denselben `SecurityStore`.

**Optionen:** `threshold` (5), `windowMs` (15 min), `lockoutSteps` (`[1m, 5m, 15m]`), `bucket`, `pepper`, `message`.

### 3.3 `basicAuth` — Credential-Prüfung

**Was:** HTTP Basic Auth für Admin-Endpoints.

**Best Practices:**
- **Constant-time-Vergleich** (`crypto.timingSafeEqual`) — schließt den Timing-Leak-Angriffsvektor, den naives `===` öffnet.
- **Length-aware** — auch bei unterschiedlichen Längen wird ein Vergleich gleicher Form ausgeführt, damit Timing keine Passwortlänge leakt.
- **Production-Guardrail** — wirft beim Startup, wenn Creds leer oder `admin`/`admin` sind und `NODE_ENV=production`. Laut scheitern statt still ausliefern.
- **Gleiche Vergleichsform bei falschem User vs. falschem Passwort** — sowohl `okUser` als auch `okPass` werden ausgewertet, selbst wenn der erste schon fehlschlägt. So kann ein Angreifer "User existiert" nicht von "falsches Passwort" unterscheiden.
- **Standard 401 + `WWW-Authenticate`**, damit Browser korrekt prompten.

**Optionen:** `username`, `password`, `realm` (`Admin`), `enforceStrongInProduction` (true).

### 3.4 `securityHeaders` — Defense-in-Depth Header

**Was:** Setzt app-weit ein kuratiertes Set an HTTP-Sicherheits-Headern.

**Best Practices:**
- **Content-Security-Policy** (Default, SPA-tauglich): `default-src 'self'`, blockiert Third-Party-Scripts/Iframes, `object-src 'none'`, `frame-ancestors 'none'`, `base-uri 'self'`. Über die Option `csp` schärfer setzbar, wenn dein Build Nonces unterstützt.
- **X-Frame-Options: DENY** + `frame-ancestors 'none'` in der CSP — Clickjacking auf zwei Ebenen blockiert.
- **X-Content-Type-Options: nosniff** — killt MIME-Sniffing-Angriffe.
- **Referrer-Policy: strict-origin-when-cross-origin** — leakt nie volle URLs cross-origin.
- **Permissions-Policy** — verbietet Geolocation/Mikrofon/Kamera explizit per Default.
- **X-XSS-Protection: 0** — deaktiviert den legacy IE/old-Chrome-Filter (hat Schwachstellen verursacht); wir verlassen uns auf die CSP. Das ist die OWASP-Empfehlung.
- **HSTS nur opt-in** — ist im Browser sticky, daher per Default nicht gesetzt für HTTP-fähige Deployments.

### 3.5 `validateBody` — Schema + Größenprüfung

**Was:** Führt ein Zod-Schema auf einem Request-Body aus, mit hartem Byte-Cap. Gibt ein Result-Objekt zurück.

**Best Practices:**
- **Schema-getriebene Validierung überall** — dem Client nie trauen; alle Writes laufen durch Zod.
- **Payload-Größenlimit** (64 KB Default) — schützt gegen Memory-Amplification, bevor das Schema überhaupt läuft.
- **Keine Exceptions über Middleware-Grenzen** — gibt `{ ok, data, errors, rejected }` zurück, sodass der Caller die HTTP-Form kontrolliert und `recordInvalid()` füttern kann.
- **`rejected` vs `!ok`** — unterscheidet "konnte nicht mal geparst werden" (vermutlich böswillig) von "valides JSON, aber Schema nicht eingehalten" (eher User-Fehler). Beides ist trotzdem ein Strike.

### 3.6 `ipUtils` — IP-Auflösung und Hashing

**Was:** Löst die echte Client-IP auf und hasht sie für die Speicherung.

**Best Practices:**
- **Trust-Proxy-bewusst** — nutzt `req.ip` (Express respektiert `trust proxy`) mit Socket-Adress-Fallback. Verhindert IP-Header-Spoofing, wenn kein vertrauter Proxy existiert.
- **Gepfeffertes Hashing** — `SHA-256("<server-secret>:<ip>")`. Ohne Pepper ist IP-Hashing Theater — der IPv4-Raum ist klein genug, um in Sekunden rainbow-getablet zu werden. Der Pepper macht den gespeicherten Hash über Deployments hinweg nicht korrelierbar.
- **Pepper via Env** (`IP_HASH_PEPPER`) mit einem als unsicher markierten Dev-Default.

### 3.7 `SecurityStore` — Austauschbare Zähler-Persistenz

**Was:** Das einzige, was die Middleware über Storage weiß. Vier Methoden: `hit`, `count`, `reset`, `prune`.

**Best Practices:**
- **Persistenz per Default** (`SqliteSecurityStore`) — Zähler überleben Prozess-Restarts, ein Neustart ist also kein Free-Abuse-Window.
- **Indexierte Queries** — `(key, ts)`-Index auf `security_events`, damit `count` O(log n) ist.
- **Throttled Pruning** — `prune()` läuft höchstens einmal pro Minute, egal wie hoch die Request-Rate ist; kein Overhead pro Request.
- **Auto-Bootstrap** — legt seine Tabelle und den Index beim ersten Gebrauch an; kein separater Migrationsschritt.
- **Interface, keine Klasse** — `SqliteSecurityStore` lässt sich gegen eine Redis-Implementierung hinter einem Load-Balancer tauschen, ohne dass die Middleware angefasst wird.

---

## 4. Die "usable security"-Prinzipien, in Code gegossen

Diese Design-Entscheidungen unterscheiden dieses Layer von einem Standard-`helmet + express-rate-limit`-Setup:

1. **Strikes werden verdient, nicht angenommen.** Volumen allein triggert nie einen Lockout; nur `recordInvalid()`. Ein echter User, der gültige Daten sendet, ist für den abuseGuard unsichtbar.
2. **Validierung ist das Abuse-Signal.** Ein Zod-Fail ist das sauberste "das ist kein legitimer User"-Signal, das du bekommen kannst. Wir füttern es direkt ins Lockout-Tracking.
3. **Goodwill bei Erfolg.** Ein gültiger Request nach mehreren Versuchen löscht den Strike-Record. Verwirrte User werden nicht bestraft, wenn sie es richtig machen.
4. **Cooldowns in Minuten, nicht Stunden.** Lang genug, um Skript-Abuse zu brechen; kurz genug, dass ein verwirrter Mensch warten kann.
5. **Per-Route-Bucketing.** Ein lauter Endpoint beeinflusst keine anderen.
6. **Production-Guardrails scheitern laut.** Schwache Admin-Creds in Production = Startup-Crash, nicht stilles Ausliefern.
7. **Header so gewählt, dass eine normale SPA noch funktioniert.** Kein `'unsafe-eval'`, aber `'unsafe-inline'` Styles erlaubt — über Option schärfbar, niemals per Default kaputt.
8. **Kein `await` in der Security-Middleware.** Synchrones SQLite + synchrone Zähler = kein TOCTOU zwischen "check" und "increment".

---

## 5. Abgedeckte (und nicht abgedeckte) Bedrohungen

### Abgedeckt
- Volumen-Abuse / Formular-Spam — `rateLimit`
- Zielgerichteter Brute-Force auf Inputs oder Login — `abuseGuard` + `basicAuth` (timing-safe)
- Müll-/Überdimensionierte Payloads — `validateBody`-Größenlimit + `express.json({ limit })`
- Clickjacking — `X-Frame-Options` + `frame-ancestors`
- MIME-Sniffing — `X-Content-Type-Options`
- XSS durch injizierte Scripts — CSP (in den Grenzen von `'unsafe-inline'` Styles)
- Referrer-Leaking — `Referrer-Policy`
- IP-Rainbow-Tabling gespeicherter Hashes — gepfefferter Hash
- Default-Creds-in-Production-Footgun — Startup-Verweigerung
- Neustart-resettet-Zähler — persistenter `SecurityStore`

### Nicht abgedeckt (per Design — out of scope)
- **Bot-Detection / CAPTCHA** — andere Ebene; bei Bedarf mit hCaptcha/Turnstile kombinieren.
- **DDoS auf Netzwerk-Ebene** — gehört zu CDN/WAF (Cloudflare, fly-proxy, etc.).
- **Session-Management / CSRF** — Basic Auth braucht keinen CSRF-Schutz; CSRF-Middleware hinzufügen, falls cookie-basierte Sessions eingeführt werden.
- **Datenbank-Ebene (SQL Injection)** — wird außerhalb des Moduls durch Drizzle/parameterisierte Queries abgehandelt.
- **Verteilte Zähler über mehrere Nodes** — `SqliteSecurityStore` ist single-process. Hinter einem Load-Balancer eine Redis-Variante von `SecurityStore` implementieren.

---

## 6. Konfigurationsoberfläche

```ts
createSecurityLayer({
  store,                       // SecurityStore (SQLite/Memory/eigene)
  pepper: process.env.IP_HASH_PEPPER,

  rateLimit:  { windowMs, max, bucket, message },
  abuseGuard: { threshold, windowMs, lockoutSteps, bucket, message },
  basicAuth:  { username, password, realm, enforceStrongInProduction },
  headers:    { csp, hsts },
})
```

Jede Komponente ist auch einzeln importierbar, falls feinere Kontrolle nötig ist.

### Umgebungsvariablen

| Var | Zweck | Pflicht? |
|---|---|---|
| `IP_HASH_PEPPER` | Geheimes Salt für IP-Hashing | **Ja in Production** |
| `ADMIN_USER` / `ADMIN_PASS` | Basic-Auth-Credentials | **Ja in Production** (Startup verweigert schwache Creds) |

---

## 7. Verdrahtungs-Muster (kanonisch)

```ts
app.set("trust proxy", 1);          // echte Client-IPs hinter Proxy
app.use(security.headers);          // app-weite Hardening-Header
app.use(express.json({ limit: "64kb" })); // Body-Cap

app.post(
  "/api/thing",
  security.rateLimit,               // Volumen-Cap
  security.abuseGuard.middleware,   // Sperre, falls aktuell blockiert
  (req, res) => {
    const r = validateBody(req.body, mySchema);
    if (!r.ok) {
      security.abuseGuard.recordInvalid(req); // Strike
      return res.status(400).json({ error: r.errors });
    }
    security.abuseGuard.recordValid(req);     // Strikes löschen
    // ... r.data persistieren ...
  },
);

app.get("/api/admin/x", security.requireAdmin!, handler);
```

Diese Reihenfolge — **Volumen → Lockout → Validieren → Outcome aufzeichnen** — ist das Rückgrat des Moduls.

---

## 8. Dateien

```
security/
├── index.ts             ← Einstiegspunkt + createSecurityLayer-Factory
├── store.ts             ← SecurityStore-Interface, SQLite- & Memory-Impls
├── rateLimit.ts         ← Sliding-Window Volumen-Cap
├── abuseGuard.ts        ← Eskalierender Lockout bei ungültiger Eingabe
├── basicAuth.ts         ← Constant-time HTTP Basic Auth
├── securityHeaders.ts   ← CSP + sichere Header
├── validate.ts          ← Zod + Größenlimit-Helper
├── ipUtils.ts           ← Trust-Proxy-IP + gepfefferter SHA-256
└── README.md            ← Copy-Paste-Setup + Optionstabelle
```

Den kompletten Ordner in ein anderes Express + SQL-Projekt droppen, einen `SqliteSecurityStore(yourDb)` durchreichen, `createSecurityLayer(...)` aufrufen — und du hast denselben Schutz. Genau das ist der Sinn.
