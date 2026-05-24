import { createHash } from "crypto";
import type { Request } from "express";

/**
 * Resolve the real client IP.
 *
 * Express only fills `req.ip` from X-Forwarded-For when `trust proxy` is set
 * (see index.ts). We still defend against the header being absent or spoofed
 * when no proxy is trusted by falling back to the socket address.
 */
export function clientIp(req: Request): string {
  return (
    req.ip ||
    (req.socket && req.socket.remoteAddress) ||
    ""
  );
}

/**
 * One-way hash of an IP for storage. We pepper it with a server secret so the
 * stored value can't be reversed with a rainbow table of the (tiny) IPv4
 * space. Without a pepper, hashing an IP is security theatre.
 *
 * Configure via the IP_HASH_PEPPER env var. A throwaway default is used in
 * dev so the app still runs, but production should always set its own.
 */
export function hashIp(ip: string, pepper?: string): string {
  const secret =
    pepper ?? process.env.IP_HASH_PEPPER ?? "dev-only-insecure-pepper";
  return createHash("sha256").update(`${secret}:${ip}`).digest("hex");
}
