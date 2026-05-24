import { z, type ZodTypeAny } from "zod";

export interface ValidateResult<T> {
  ok: boolean;
  data?: T;
  /** Flattened zod errors, safe to send to the client. */
  errors?: unknown;
  /** True when the body was rejected before parsing (too large / not an object). */
  rejected?: boolean;
}

export interface ValidateOptions {
  /** Reject bodies whose JSON string exceeds this many bytes. Default 64 KB. */
  maxBytes?: number;
}

/**
 * Validate a request body against a Zod schema with a hard size cap.
 *
 * Returns a result object instead of throwing so the caller decides the HTTP
 * shape. A `rejected` or `!ok` result is exactly what you feed into
 * abuseGuard.recordInvalid() - invalid input is the signal abuse tracking
 * keys off, never valid submissions.
 */
export function validateBody<S extends ZodTypeAny>(
  body: unknown,
  schema: S,
  opts: ValidateOptions = {},
): ValidateResult<z.infer<S>> {
  const maxBytes = opts.maxBytes ?? 64 * 1024;

  if (body == null || typeof body !== "object") {
    return { ok: false, rejected: true, errors: { _: ["Invalid request body"] } };
  }

  // Cheap oversize guard (Express's json limit is the real one; this is depth-2).
  let size = 0;
  try {
    size = Buffer.byteLength(JSON.stringify(body), "utf8");
  } catch {
    return { ok: false, rejected: true, errors: { _: ["Unserializable body"] } };
  }
  if (size > maxBytes) {
    return { ok: false, rejected: true, errors: { _: ["Payload too large"] } };
  }

  const parsed = schema.safeParse(body);
  if (!parsed.success) {
    return { ok: false, errors: parsed.error.flatten() };
  }
  return { ok: true, data: parsed.data };
}
