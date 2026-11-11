/**
 * Span events streamed from interact / crawl workflow runs and rendered by
 * the trace view. Kept free of Node APIs so the workflow body and the
 * browser bundle can both import it.
 */

export type SpanStatus = "running" | "ok" | "failed" | "skipped";
export type SpanKind =
  | "setup"
  | "open"
  | "action"
  | "read"
  | "map"
  | "page"
  | "charge"
  | "fetch"
  | "ocr"
  | "transcribe";

export interface Span {
  /** Stable id within a run, e.g. `action-3`. Later events with the same id replace earlier ones. */
  id: string;
  kind: SpanKind;
  label: string;
  detail?: string;
  status: SpanStatus;
  /** Milliseconds since the run started. */
  startMs: number;
  durationMs?: number;
  error?: string;
}

export type RunEvent =
  | { type: "run"; runId: string; kind: "interact" | "crawl" | "parse"; url: string; startedAt: number }
  | { type: "span"; span: Span }
  | { type: "done"; status: "completed" | "failed"; error?: string };

/** Folds a list of events into the latest state of each span, in first-seen order. */
export function foldSpans(events: RunEvent[]): Span[] {
  const order: string[] = [];
  const byId = new Map<string, Span>();
  for (const e of events) {
    if (e.type !== "span") continue;
    if (!byId.has(e.span.id)) order.push(e.span.id);
    byId.set(e.span.id, e.span);
  }
  return order.map((id) => byId.get(id)!);
}

export interface SpanSummary {
  total: number;
  ok: number;
  failed: number;
  skipped: number;
  running: number;
  durationMs: number;
  /** 1-based index among spans of the given kind, of the first failure. */
  firstFailedIndex?: number;
}

export function summarizeSpans(spans: Span[], kind?: SpanKind): SpanSummary {
  const list = kind ? spans.filter((s) => s.kind === kind) : spans;
  let durationMs = 0;
  let firstFailedIndex: number | undefined;
  const s = { total: list.length, ok: 0, failed: 0, skipped: 0, running: 0 };
  list.forEach((span, i) => {
    s[span.status === "ok" ? "ok" : span.status] += 1;
    if (span.status === "failed" && firstFailedIndex === undefined) firstFailedIndex = i + 1;
  });
  for (const span of spans) durationMs = Math.max(durationMs, span.startMs + (span.durationMs ?? 0));
  return { ...s, durationMs, firstFailedIndex };
}
