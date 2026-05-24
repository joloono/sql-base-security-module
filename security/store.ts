/**
 * SecurityStore - pluggable persistence for rate-limit / abuse-guard counters.
 *
 * The whole point of this interface is that the security layer never talks to
 * a concrete database. Ship with SQLite today, swap to Postgres/Redis later
 * without touching the middleware.
 *
 * A "hit" is one recorded event for a (key) at a timestamp. Keys are opaque
 * strings the middleware builds (e.g. `rl:POST /api/rsvp:<iphash>`).
 */
export interface SecurityStore {
  /**
   * Record one hit for `key` at `now` (ms epoch) and return how many hits
   * for that key happened within the last `windowMs`.
   */
  hit(key: string, now: number, windowMs: number): number;

  /** Count hits for `key` within `windowMs` WITHOUT recording a new one. */
  count(key: string, now: number, windowMs: number): number;

  /** Forget all hits for `key` (e.g. after a successful, valid request). */
  reset(key: string): void;

  /** Delete hits older than `now - maxAgeMs` across all keys. Housekeeping. */
  prune(now: number, maxAgeMs: number): void;
}

/**
 * better-sqlite3 is synchronous, so this store is synchronous too - which
 * keeps the middleware free of await and race conditions. It only needs a
 * handle exposing `.prepare()` (a better-sqlite3 Database, or anything
 * API-compatible). No Drizzle dependency on purpose: this module stays
 * portable.
 */
interface SqliteLike {
  prepare(sql: string): {
    run(...params: unknown[]): unknown;
    get(...params: unknown[]): unknown;
    all(...params: unknown[]): unknown[];
  };
  exec(sql: string): unknown;
}

export class SqliteSecurityStore implements SecurityStore {
  private lastPrune = 0;

  constructor(
    private db: SqliteLike,
    private table = "security_events",
  ) {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS ${this.table} (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT NOT NULL,
        ts  INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_${this.table}_key_ts
        ON ${this.table} (key, ts);
    `);
  }

  hit(key: string, now: number, windowMs: number): number {
    this.db.prepare(`INSERT INTO ${this.table} (key, ts) VALUES (?, ?)`).run(key, now);
    return this.count(key, now, windowMs);
  }

  count(key: string, now: number, windowMs: number): number {
    const row = this.db
      .prepare(`SELECT COUNT(*) AS n FROM ${this.table} WHERE key = ? AND ts > ?`)
      .get(key, now - windowMs) as { n: number } | undefined;
    return row?.n ?? 0;
  }

  reset(key: string): void {
    this.db.prepare(`DELETE FROM ${this.table} WHERE key = ?`).run(key);
  }

  prune(now: number, maxAgeMs: number): void {
    // Throttle: pruning every request would be wasteful. Once a minute is plenty.
    if (now - this.lastPrune < 60_000) return;
    this.lastPrune = now;
    this.db.prepare(`DELETE FROM ${this.table} WHERE ts < ?`).run(now - maxAgeMs);
  }
}

/**
 * In-memory fallback. Good for tests or single-process dev without a DB.
 * Not durable and not multi-process safe - do not use behind a load balancer.
 */
export class MemorySecurityStore implements SecurityStore {
  private events = new Map<string, number[]>();

  hit(key: string, now: number, windowMs: number): number {
    const arr = (this.events.get(key) ?? []).filter((t) => t > now - windowMs);
    arr.push(now);
    this.events.set(key, arr);
    return arr.length;
  }

  count(key: string, now: number, windowMs: number): number {
    return (this.events.get(key) ?? []).filter((t) => t > now - windowMs).length;
  }

  reset(key: string): void {
    this.events.delete(key);
  }

  prune(now: number, maxAgeMs: number): void {
    for (const key of Array.from(this.events.keys())) {
      const kept = (this.events.get(key) ?? []).filter(
        (t: number) => t > now - maxAgeMs,
      );
      if (kept.length) this.events.set(key, kept);
      else this.events.delete(key);
    }
  }
}
