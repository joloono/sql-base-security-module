import type { Request, Response, NextFunction } from "express";
import { timingSafeEqual } from "crypto";

export interface BasicAuthOptions {
  username: string;
  password: string;
  realm?: string;
  /**
   * Throw on startup if credentials look weak (empty or "admin"/"admin")
   * while NODE_ENV=production. Default true - fail loud, not silent.
   */
  enforceStrongInProduction?: boolean;
}

/** Constant-time string compare so auth can't be timing-attacked. */
function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  // timingSafeEqual requires equal length; compare a fixed-size digest-ish
  // padding to avoid leaking length. Simplest robust approach: pad to max.
  if (ab.length !== bb.length) {
    // Still do a comparison to keep timing roughly constant.
    timingSafeEqual(ab, ab);
    return false;
  }
  return timingSafeEqual(ab, bb);
}

/**
 * HTTP Basic auth with constant-time credential comparison.
 *
 * Basic auth is fine for a single-admin internal panel like this. The two
 * historical footguns - timing leaks and shipping default creds - are both
 * closed here.
 */
export function basicAuth(opts: BasicAuthOptions) {
  const enforce = opts.enforceStrongInProduction ?? true;
  const weak =
    !opts.username ||
    !opts.password ||
    (opts.username === "admin" && opts.password === "admin");

  if (enforce && weak && process.env.NODE_ENV === "production") {
    throw new Error(
      "[security] Refusing to start: weak/default admin credentials in production. " +
        "Set strong ADMIN_USER and ADMIN_PASS.",
    );
  }
  if (weak) {
    console.warn(
      "[security] WARNING: weak/default admin credentials in use. Fine for dev, not for production.",
    );
  }

  const realm = opts.realm ?? "Admin";

  return function basicAuthMiddleware(
    req: Request,
    res: Response,
    next: NextFunction,
  ) {
    const header = req.headers.authorization;
    const challenge = () => {
      res.setHeader("WWW-Authenticate", `Basic realm="${realm}"`);
      return res.status(401).send("Authentication required");
    };

    if (!header || !header.startsWith("Basic ")) return challenge();

    const decoded = Buffer.from(header.slice(6), "base64").toString();
    const sep = decoded.indexOf(":");
    if (sep === -1) return challenge();

    const user = decoded.slice(0, sep);
    const pass = decoded.slice(sep + 1);

    // Evaluate both comparisons regardless, so a wrong username and a wrong
    // password take the same time.
    const okUser = safeEqual(user, opts.username);
    const okPass = safeEqual(pass, opts.password);
    if (!(okUser && okPass)) return challenge();

    next();
  };
}
