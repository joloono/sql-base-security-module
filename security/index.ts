/**
 * Reusable SQL-app security hardening layer.
 * ------------------------------------------
 * Drop this whole `security/` folder into any Express + SQL project.
 * It has ZERO project-specific code. Wire it up with createSecurityLayer().
 *
 * Goal: meaningfully harder to abuse, without getting in honest users' way.
 *   - rate limit       -> caps request volume per IP (loose defaults)
 *   - abuse guard      -> escalating lockout, triggered ONLY by invalid input
 *   - basic auth       -> constant-time, refuses weak creds in prod
 *   - security headers  -> safe defaults that don't break a SPA
 *   - validate          -> zod + size cap, feeds the abuse guard
 *   - SecurityStore     -> swap SQLite today for Postgres/Redis later
 *
 * See README.md in this folder for the options table and copy-paste setup.
 */
export { type SecurityStore, SqliteSecurityStore, MemorySecurityStore } from "./store";
export { clientIp, hashIp } from "./ipUtils";
export { rateLimit, type RateLimitOptions } from "./rateLimit";
export { createAbuseGuard, type AbuseGuard, type AbuseGuardOptions } from "./abuseGuard";
export { basicAuth, type BasicAuthOptions } from "./basicAuth";
export { securityHeaders, type SecurityHeadersOptions } from "./securityHeaders";
export { validateBody, type ValidateResult, type ValidateOptions } from "./validate";

import type { SecurityStore } from "./store";
import { rateLimit, type RateLimitOptions } from "./rateLimit";
import { createAbuseGuard, type AbuseGuard } from "./abuseGuard";
import { basicAuth, type BasicAuthOptions } from "./basicAuth";
import { securityHeaders, type SecurityHeadersOptions } from "./securityHeaders";

export interface SecurityLayerOptions {
  store: SecurityStore;
  /** Shared pepper for IP hashing across all sub-components. */
  pepper?: string;
  rateLimit?: Omit<RateLimitOptions, "store" | "pepper">;
  abuseGuard?: Omit<
    Parameters<typeof createAbuseGuard>[0],
    "store" | "pepper"
  >;
  basicAuth?: BasicAuthOptions;
  headers?: SecurityHeadersOptions;
}

export interface SecurityLayer {
  /** App-wide hardening headers. Mount with app.use(). */
  headers: ReturnType<typeof securityHeaders>;
  /** Per-route volume limiter. */
  rateLimit: ReturnType<typeof rateLimit>;
  /** Invalid-input lockout. Use .middleware + .recordInvalid/.recordValid. */
  abuseGuard: AbuseGuard;
  /** Admin basic-auth middleware (only if basicAuth options were given). */
  requireAdmin?: ReturnType<typeof basicAuth>;
}

/**
 * One call wires the whole layer with sensible, usability-first defaults.
 * Everything is still individually importable if you want finer control.
 */
export function createSecurityLayer(opts: SecurityLayerOptions): SecurityLayer {
  const pepper = opts.pepper;

  return {
    headers: securityHeaders(opts.headers),
    rateLimit: rateLimit({ store: opts.store, pepper, ...opts.rateLimit }),
    abuseGuard: createAbuseGuard({
      store: opts.store,
      pepper,
      ...opts.abuseGuard,
    }),
    requireAdmin: opts.basicAuth ? basicAuth(opts.basicAuth) : undefined,
  };
}
