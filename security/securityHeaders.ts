import type { Request, Response, NextFunction } from "express";

export interface SecurityHeadersOptions {
  /**
   * Send HSTS. Only enable when you serve HTTPS everywhere - it's sticky in
   * browsers. Default false so local/HTTP dev isn't bricked.
   */
  hsts?: boolean;
  /**
   * Content-Security-Policy string. Default is intentionally permissive
   * enough for a Vite/React SPA (inline styles, same-origin scripts) while
   * still blocking the obvious XSS vectors. Pass your own to tighten.
   * Set to null to omit CSP entirely.
   */
  csp?: string | null;
}

const DEFAULT_CSP = [
  "default-src 'self'",
  "img-src 'self' data: blob:",
  // Vite-built bundles are same-origin; styles often inlined by the toolchain.
  "style-src 'self' 'unsafe-inline'",
  "script-src 'self'",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'self'",
  "frame-ancestors 'none'",
].join("; ");

/**
 * A minimal, framework-agnostic set of hardening headers. Deliberately not
 * "helmet with everything on" - only headers that don't risk breaking a
 * normal SPA are on by default. Usability first; opt in to the strict ones.
 */
export function securityHeaders(opts: SecurityHeadersOptions = {}) {
  const csp = opts.csp === undefined ? DEFAULT_CSP : opts.csp;

  return function securityHeadersMiddleware(
    _req: Request,
    res: Response,
    next: NextFunction,
  ) {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    res.setHeader("X-XSS-Protection", "0"); // modern browsers: CSP, not the legacy filter
    res.setHeader(
      "Permissions-Policy",
      "geolocation=(), microphone=(), camera=()",
    );
    if (csp) res.setHeader("Content-Security-Policy", csp);
    if (opts.hsts) {
      res.setHeader(
        "Strict-Transport-Security",
        "max-age=15552000; includeSubDomains",
      );
    }
    next();
  };
}
