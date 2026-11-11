/**
 * Input checks for /v1/interact. Pure functions so they can be unit-tested
 * and reused by the API route before a workflow run is started.
 */

export const INTERACT_ACTION_TYPES = [
  "click",
  "fill",
  "type",
  "hover",
  "select",
  "press",
  "wait",
  "scroll",
  "evaluate",
  "extract",
] as const;

export type InteractActionType = (typeof INTERACT_ACTION_TYPES)[number];

export const MAX_INTERACT_ACTIONS = 20;

export interface InteractAction {
  type: InteractActionType;
  selector?: string;
  text?: string;
  value?: string;
  key?: string;
  ms?: number;
  y?: number;
  script?: string;
  timeoutMs?: number;
}

/** Browser session length: 2 min by default (first minute in the base price), 10 min max. */
export const DEFAULT_SESSION_SECONDS = 120;
export const MAX_SESSION_SECONDS = 600;

export type ValidateResult =
  | { ok: true; url: string; actions: InteractAction[]; sessionSeconds: number }
  | { ok: false; error: string };

const NEEDS_SELECTOR = new Set<InteractActionType>(["click", "fill", "type", "hover", "select", "extract"]);
const ALIASES: Record<string, InteractActionType> = {
  input: "fill",
  write: "fill",
  keypress: "press",
  scrape: "extract",
  wait_for: "wait",
  waitfor: "wait",
  js: "evaluate",
  execute: "evaluate",
};

const str = (v: unknown): string | undefined =>
  typeof v === "string" ? v : typeof v === "number" ? String(v) : undefined;
const num = (v: unknown): number | undefined => {
  const n = typeof v === "string" ? Number(v) : v;
  return typeof n === "number" && Number.isFinite(n) ? n : undefined;
};

export function normalizeActionType(raw: unknown): InteractActionType | undefined {
  const t = String(raw ?? "").trim().toLowerCase();
  if ((INTERACT_ACTION_TYPES as readonly string[]).includes(t)) return t as InteractActionType;
  return ALIASES[t];
}

/** Human label used in the trace, e.g. `Click  #submit`. */
export function describeAction(a: InteractAction): string {
  switch (a.type) {
    case "wait":
      return a.selector ? "Wait for element" : `Wait ${a.ms ?? 500}ms`;
    case "scroll":
      return a.selector ? "Scroll to element" : `Scroll ${a.y ?? 800}px`;
    case "press":
      return `Press ${a.key ?? "Enter"}`;
    case "fill":
      return "Fill";
    case "evaluate":
      return "Run script";
    default:
      return a.type.charAt(0).toUpperCase() + a.type.slice(1);
  }
}

export function validateInteractRequest(body: Record<string, unknown>): ValidateResult {
  const rawUrl = str(body.url)?.trim() ?? "";
  if (!rawUrl) return { ok: false, error: "Missing `url` parameter" };
  let url: string;
  try {
    const parsed = new URL(/^https?:\/\//i.test(rawUrl) ? rawUrl : `https://${rawUrl}`);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") throw new Error();
    url = parsed.toString();
  } catch {
    return { ok: false, error: `Invalid url: ${rawUrl}` };
  }

  const rawActions: unknown[] = Array.isArray(body.actions)
    ? body.actions
    : body.selector
      ? [{ type: "extract", selector: body.selector }]
      : [];

  if (rawActions.length > MAX_INTERACT_ACTIONS) {
    return { ok: false, error: `Too many actions (${rawActions.length}). The limit is ${MAX_INTERACT_ACTIONS}.` };
  }

  const actions: InteractAction[] = [];
  for (let i = 0; i < rawActions.length; i++) {
    const raw = rawActions[i];
    const a: Record<string, unknown> =
      typeof raw === "object" && raw !== null ? (raw as Record<string, unknown>) : { type: raw };
    const type = normalizeActionType(a.type ?? a.action);
    const at = `actions[${i}]`;
    if (!type) {
      return {
        ok: false,
        error: `${at}: unknown type ${JSON.stringify(a.type ?? a.action ?? null)}. Valid types: ${INTERACT_ACTION_TYPES.join(", ")}.`,
      };
    }
    const selector = str(a.selector)?.trim() || undefined;
    if (NEEDS_SELECTOR.has(type) && !selector) {
      return { ok: false, error: `${at}: \`${type}\` needs a \`selector\`.` };
    }
    const action: InteractAction = { type };
    if (selector) action.selector = selector.slice(0, 500);
    const text = str(a.text) ?? str(a.value);
    if (type === "fill" || type === "type") {
      if (text === undefined) return { ok: false, error: `${at}: \`${type}\` needs \`text\`.` };
      action.text = text.slice(0, 5000);
    }
    if (type === "select") {
      if (text === undefined) return { ok: false, error: `${at}: \`select\` needs a \`value\`.` };
      action.value = text.slice(0, 500);
    }
    if (type === "press") action.key = (str(a.key) ?? "Enter").slice(0, 40);
    if (type === "wait" && !selector) {
      action.ms = Math.max(0, Math.min(num(a.ms ?? a.milliseconds) ?? 500, 15_000));
    }
    if (type === "scroll" && !selector) action.y = Math.max(-20_000, Math.min(num(a.y ?? a.amount) ?? 800, 20_000));
    if (type === "evaluate") {
      const script = str(a.script ?? a.expression ?? a.code);
      if (!script) return { ok: false, error: `${at}: \`evaluate\` needs a \`script\`.` };
      if (script.length > 10_000) return { ok: false, error: `${at}: script is longer than 10,000 characters.` };
      action.script = script;
    }
    const timeoutMs = num(a.timeoutMs ?? a.timeout);
    if (timeoutMs !== undefined) action.timeoutMs = Math.max(500, Math.min(timeoutMs, 30_000));
    actions.push(action);
  }

  const rawSession = num(body.sessionSeconds ?? body.timeoutSeconds);
  const sessionSeconds = Math.round(
    Math.max(30, Math.min(rawSession ?? DEFAULT_SESSION_SECONDS, MAX_SESSION_SECONDS))
  );

  return { ok: true, url, actions, sessionSeconds };
}
