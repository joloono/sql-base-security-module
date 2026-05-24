import type { Request, Response, NextFunction } from "express";
import type { SecurityStore } from "./store";
import { clientIp, hashIp } from "./ipUtils";

export interface RateLimitOptions {
  store: SecurityStore;
  /** Sliding window length in ms. Default 10 minutes. */
  windowMs?: number;
  /** Max requests per IP per window. Default 10 - generous for honest use. */
  max?: number;
  /** Namespace so multiple routes don't share one bucket. Default = method+path. */
  bucket?: string;
  /** Pepper for IP hashing (keeps keys non-reversible). */
  pepper?: string;
  /** Response when the limit is exceeded. */
  message?: string;
}

/**
 * Sliding-window rate limit, per IP, per route.
 *
 * Philosophy: this throttles *volume*, not correctness. Defaults are
 * deliberately loose - a whole family filling in one RSVP form, retrying a
 * couple of times, will never hit 10 requests / 10 min. Tighten via options
 * only where a route genuinely needs it.
 */
export function rateLimit(opts: RateLimitOptions) {
  const windowMs = opts.windowMs ?? 10 * 60 * 1000;
  const max = opts.max ?? 10;

  return function rateLimitMiddleware(
    req: Request,
    res: Response,
    next: NextFunction,
  ) {
    const now = Date.now();
    opts.store.prune(now, Math.max(windowMs, 60 * 60 * 1000));

    const bucket = opts.bucket ?? `${req.method} ${req.path}`;
    const ipKey = hashIp(clientIp(req), opts.pepper);
    const key = `rl:${bucket}:${ipKey}`;

    const hits = opts.store.hit(key, now, windowMs);
    const remaining = Math.max(0, max - hits);

    res.setHeader("RateLimit-Limit", String(max));
    res.setHeader("RateLimit-Remaining", String(remaining));

    if (hits > max) {
      res.setHeader("Retry-After", String(Math.ceil(windowMs / 1000)));
      return res.status(429).json({
        error: opts.message ?? "Too many requests. Please try again later.",
      });
    }
    next();
  };
}
