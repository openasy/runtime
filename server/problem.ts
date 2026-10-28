export type ProblemCode = "invalid-token" | "invalid-json" | "invalid-body" | "not-found" | "conflict" | "payload-too-large" | "internal-error";

/** An error the API answers with Problem Details (ADR 0014); `code` is the stable part clients match on. */
export class RuntimeError extends Error {
  readonly status: number;
  readonly code: ProblemCode;
  constructor(status: number, code: ProblemCode, detail: string) {
    super(detail);
    this.status = status;
    this.code = code;
  }
}

export const bad = (detail: string) => new RuntimeError(422, "invalid-body", detail);
export const notFound = (what: string) => new RuntimeError(404, "not-found", `${what} does not exist.`);
export const conflict = (detail: string) => new RuntimeError(409, "conflict", detail);

/** A plain object from a request body, or undefined. */
export const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

/** Refuses fields a body may not have, so a typo is an error rather than a setting silently left out. */
export function only(b: Record<string, unknown>, allowed: string[], shape: string) {
  const extra = Object.keys(b).filter((k) => !allowed.includes(k));
  if (extra.length) throw bad(`Unknown field ${extra[0]}. Expected ${shape}.`);
}
