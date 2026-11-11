export type WebcrawlErrorKind =
  | "auth"
  | "credits"
  | "rate_limit"
  | "bad_request"
  | "not_found"
  | "server"
  | "network"
  | "timeout";

export class WebcrawlError extends Error {
  readonly kind: WebcrawlErrorKind;
  readonly status?: number;
  /** Seconds to wait before retrying, from `Retry-After` on 429. */
  readonly retryAfter?: number;
  readonly body?: unknown;

  constructor(
    kind: WebcrawlErrorKind,
    message: string,
    opts: { status?: number; retryAfter?: number; body?: unknown } = {}
  ) {
    super(message);
    this.name = "WebcrawlError";
    this.kind = kind;
    this.status = opts.status;
    this.retryAfter = opts.retryAfter;
    this.body = opts.body;
  }
}

export function kindForStatus(status: number): WebcrawlErrorKind {
  if (status === 401 || status === 403) {return "auth";}
  if (status === 402) {return "credits";}
  if (status === 429) {return "rate_limit";}
  if (status === 404) {return "not_found";}
  if (status >= 500) {return "server";}
  return "bad_request";
}

/** One actionable sentence for people (and models) reading the error. */
export function describeError(err: unknown, baseUrl = "https://webcrawl.app"): string {
  if (!(err instanceof WebcrawlError)) {
    return err instanceof Error ? err.message : String(err);
  }
  switch (err.kind) {
    case "auth":
      return "Your API key is missing or invalid. Set WEBCRAWL_API_KEY or run `webcrawl login`.";
    case "credits":
      return `You are out of credits. Add more at ${baseUrl}/account.`;
    case "rate_limit":
      return err.retryAfter
        ? `Rate limited. Retry in ${err.retryAfter}s.`
        : "Rate limited. Wait a moment and retry.";
    case "timeout":
      return "The request timed out. Try again, or narrow the request.";
    case "network":
      return `Could not reach ${baseUrl}. Check your connection or WEBCRAWL_URL.`;
    default:
      return err.message;
  }
}
