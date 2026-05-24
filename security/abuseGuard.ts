import type { Request, Response, NextFunction } from "express";
import type { SecurityStore } from "./store";
import { clientIp, hashIp } from "./ipUtils";

export interface AbuseGuardOptions {
  store: SecurityStore;
  /** How many *invalid* attempts before the first lockout. Default 5. */
  threshold?: number;
  /** Window over which invalid attempts accumulate (ms). Default 15 min. */
  windowMs?: number;
  /**
   * Escalating cooldowns (ms) applied once threshold is crossed. The Nth
   * lockout in a row uses lockoutSteps[min(N-1, len-1)].
   * Default: 1 min -> 5 min -> 15 min.
   */
  lockoutSteps?: number[];
  bucket?: string;
  pepper?: string;
  message?: string;
}

export interface AbuseGuard {
  /** Middleware: blocks the request if the IP is currently locked out. */
  middleware: (req: Request, res: Response, next: NextFunction) => void;
  /** Call when a request from this IP turned out to be invalid/abusive. */
  recordInvalid: (req: Request) => void;
  /** Call after a fully valid request - clears that IP's strike record. */
  recordValid: (req: Request) => void;
}

/**
 * Progressive lockout that punishes *bad* traffic only.
 *
 * Key design choice for "secure without hurting usability": a normal user who
 * submits a valid form is never counted here at all. Strikes are only added by
 * recordInvalid() (failed validation, garbage payloads, auth brute force).
 * After `threshold` strikes the IP gets a short, escalating timeout - minutes,
 * not hours - and any valid submission wipes the slate clean.
 */
export function createAbuseGuard(opts: AbuseGuardOptions): AbuseGuard {
  const threshold = opts.threshold ?? 5;
  const windowMs = opts.windowMs ?? 15 * 60 * 1000;
  const steps = opts.lockoutSteps ?? [60_000, 5 * 60_000, 15 * 60_000];

  const strikeKey = (req: Request) => {
    const bucket = opts.bucket ?? `${req.method} ${req.path}`;
    return `ab:${bucket}:${hashIp(clientIp(req), opts.pepper)}`;
  };

  return {
    middleware(req: Request, res: Response, next: NextFunction) {
      const now = Date.now();
      const key = strikeKey(req);
      const strikes = opts.store.count(key, now, windowMs);

      if (strikes >= threshold) {
        // How many full thresholds deep are we? -> escalate.
        const level = Math.floor(strikes / threshold) - 1;
        const cooldown = steps[Math.min(level, steps.length - 1)];

        // Locked out only if the most recent strike is still inside cooldown.
        const recent = opts.store.count(key, now, cooldown);
        if (recent > 0) {
          res.setHeader("Retry-After", String(Math.ceil(cooldown / 1000)));
          return res.status(429).json({
            error:
              opts.message ??
              "Too many invalid attempts. Please wait briefly and try again.",
          });
        }
      }
      next();
    },

    recordInvalid(req: Request) {
      opts.store.hit(strikeKey(req), Date.now(), windowMs);
    },

    recordValid(req: Request) {
      opts.store.reset(strikeKey(req));
    },
  };
}
