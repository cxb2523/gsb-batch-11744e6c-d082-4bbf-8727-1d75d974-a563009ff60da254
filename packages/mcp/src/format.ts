/** Hard cap on text returned by any tool so one call cannot flood the model context. */
export const MAX_OUTPUT_CHARS = 24_000;

export function truncate(text: string, max = MAX_OUTPUT_CHARS): string {
  if (text.length <= max) {return text;}
  return `${text.slice(0, max)}\n\n[truncated ${text.length - max} characters]`;
}

type Rec = Record<string, unknown>;
const isRec = (v: unknown): v is Rec => !!v && typeof v === "object" && !Array.isArray(v);
const str = (v: unknown): string => (typeof v === "string" ? v : typeof v === "number" ? String(v) : "");
const first = (o: Rec, keys: string[]): string => {
  for (const k of keys) {
    const v = str(o[k]);
    if (v) {return v;}
  }
  return "";
};

const VERTICALS = ["products", "offers", "listings", "flights", "hotels", "businesses", "cves"] as const;

function cveLine(o: Rec, i: number): string {
  const score = str(o.cvssScore);
  const sev = str(o.severity);
  const affected = Array.isArray(o.affected) ? o.affected.filter(isRec) : [];
  const aff = affected
    .slice(0, 3)
    .map((a) => [str(a.product), str(a.versions), a.fixed ? `fixed ${str(a.fixed)}` : ""].filter(Boolean).join(" "))
    .join("; ");
  const head = [score && `CVSS ${score}`, sev, o.kev === true ? "KEV" : "", str(o.published).slice(0, 10)]
    .filter(Boolean)
    .join(" · ");
  const summary = (str(o.title) || str(o.summary)).slice(0, 220);
  return `${i + 1}. ${str(o.id)}${head ? ` (${head})` : ""}${summary ? `\n   ${summary}` : ""}${aff ? `\n   affected: ${aff}` : ""}${o.url ? `\n   ${str(o.url)}` : ""}`;
}

function line(o: Rec, i: number): string {
  const title = first(o, ["title", "name", "address", "airline", "productName"]) || "(untitled)";
  const price = first(o, ["priceText", "price", "pricePerNight", "minPrice"]);
  const src = first(o, ["provider", "portal", "vendor", "domain", "source"]);
  const url = first(o, ["url", "link"]);
  const meta = [price, src].filter(Boolean).join(" · ");
  return `${i + 1}. ${title}${meta ? ` (${meta})` : ""}${url ? `\n   ${url}` : ""}`;
}

/** Compact, model-friendly digest of a search response. */
export function formatSearch(res: Rec): string {
  const parts: string[] = [];
  for (const key of VERTICALS) {
    const arr = res[key];
    if (Array.isArray(arr) && arr.length) {
      parts.push(`${key} (${arr.length}):\n${arr.filter(isRec).map(key === "cves" ? cveLine : line).join("\n")}`);
    }
  }
  const results = Array.isArray(res.results) ? res.results : Array.isArray(res.data) ? res.data : [];
  if (results.length) {
    parts.push(
      `results (${results.length}):\n${results
        .filter(isRec)
        .map((r, i) => {
          const desc = first(r, ["description", "snippet"]).slice(0, 240);
          return `${line(r, i)}${desc ? `\n   ${desc}` : ""}`;
        })
        .join("\n")}`
    );
  }
  if (parts.length) return parts.join("\n\n");
  if (res.success === false && str(res.error)) return `Error: ${str(res.error)}`;
  return "No results.";
}

export function formatCredits(res: Rec): string {
  const c = res.credits;
  if (!isRec(c)) {return "";}
  const bits = [
    typeof c.charged === "number" ? `charged ${c.charged}` : "",
    typeof c.remaining === "number" ? `${c.remaining} remaining` : "",
  ].filter(Boolean);
  return bits.length ? `\n\n[credits: ${bits.join(", ")}]` : "";
}

export function formatScrape(res: Rec): string {
  if (res.success === false && str(res.error)) {return `Error: ${str(res.error)}`;}
  const d = isRec(res.data) ? res.data : res;
  const title = str(d.title) || (isRec(d.metadata) ? str(d.metadata.title) : "");
  const md = str(d.markdown) || str(d.content);
  return `${title ? `# ${title}\n\n` : ""}${md || "(no content returned)"}`;
}

/** Markdown plus a one-line note on how the file was read (and what was not). */
export function formatParse(res: Rec): string {
  if (typeof res.id === "string" && res.status === "running") {
    return `Parsing in the background (run ${res.id}). Check it with web_parse_status.`;
  }
  const meta = isRec(res.metadata) && isRec(res.metadata.parse) ? res.metadata.parse : {};
  const notes: string[] = [];
  if (typeof meta.kind === "string") {notes.push(meta.kind);}
  if (typeof meta.pages === "number") {notes.push(`${meta.pages} pages`);}
  if (Array.isArray(meta.pagesOcr) && meta.pagesOcr.length) {notes.push(`OCR on pages ${meta.pagesOcr.join(", ")}`);}
  if (Array.isArray(meta.pagesSkipped) && meta.pagesSkipped.length) {
    notes.push(`not read: ${meta.pagesSkipped.filter(isRec).map((s) => `p${s.page} (${str(s.reason)})`).join(", ")}`);
  }
  if (typeof meta.durationSeconds === "number") {notes.push(`${Math.round(meta.durationSeconds)}s of audio`);}
  const warnings = Array.isArray(meta.warnings) ? meta.warnings.filter((w): w is string => typeof w === "string") : [];
  const head = notes.length ? `[${notes.join("; ")}]\n\n` : "";
  const tail = warnings.length ? `\n\n[warnings: ${warnings.join(" | ")}]` : "";
  return head + formatScrape(res) + tail;
}

export function formatMap(res: Rec): string {
  const links = Array.isArray(res.links) ? res.links : Array.isArray(res.urls) ? res.urls : [];
  const urls = links.map((l) => (isRec(l) ? str(l.url) : str(l))).filter(Boolean);
  return urls.length ? `${urls.length} URLs:\n${urls.join("\n")}` : "No URLs found.";
}

export function formatCrawl(res: Rec): string {
  const pages = Array.isArray(res.data) ? res.data : Array.isArray(res.pages) ? res.pages : [];
  if (!pages.length) {return "No pages crawled.";}
  const perPage = Math.max(1_000, Math.floor(MAX_OUTPUT_CHARS / pages.length));
  return pages
    .filter(isRec)
    .map((p) => {
      const url = str(p.url) || (isRec(p.metadata) ? str(p.metadata.sourceURL) || str(p.metadata.url) : "");
      return `## ${str(p.title) || url || "page"}\n${url}\n\n${truncate(str(p.markdown), perPage)}`;
    })
    .join("\n\n---\n\n");
}

function formatMonitorSummaryLine(m: Rec, i?: number): string {
  const prefix = i !== undefined ? `${i + 1}. ` : "";
  const id = str(m.id);
  const name = str(m.name) || str(m.url) || "(unnamed watch)";
  const status = str(m.status) || "active";
  const mode = str(m.mode) || "page";
  const urls = Array.isArray(m.urls) ? m.urls.map(str).filter(Boolean) : [];
  const scopeLabel =
    mode === "site"
      ? `site (up to ${str(m.maxPages) || "5"} pages)`
      : mode === "urls"
        ? `${urls.length || 1} URLs`
        : "single page";
  const interval = typeof m.intervalMinutes === "number" ? `every ${m.intervalMinutes}m` : "";
  const condExpr = str(m.conditionJev) || (typeof m.condition === "string" ? m.condition : "");
  const goal = condExpr ? `rule: ${condExpr}` : str(m.watchFor) ? `goal: ${str(m.watchFor)}` : "any change";
  const condMet =
    typeof m.lastConditionMet === "boolean"
      ? m.lastConditionMet
        ? "triggered"
        : "waiting"
      : "";
  const meta = [status, scopeLabel, interval, condMet].filter(Boolean).join(" · ");
  const diff = str(m.lastDiffSummary);
  return [
    `${prefix}${name} [${id}] (${meta})`,
    `   URL: ${str(m.url)}${urls.length > 1 ? ` (+${urls.length - 1} more)` : ""}`,
    `   Watch: ${goal}`,
    diff ? `   Latest: ${diff}` : "",
  ]
    .filter(Boolean)
    .join("\n");
}

export function formatMonitor(res: Rec): string {
  if (res.deleted === true) {
    return "Monitor deleted.";
  }
  if (Array.isArray(res.monitors)) {
    const list = res.monitors.filter(isRec);
    if (!list.length) {return "No active watches.";}
    return `monitors (${list.length}):\n${list.map((m, i) => formatMonitorSummaryLine(m, i)).join("\n\n")}`;
  }
  const m = isRec(res.monitor) ? res.monitor : isRec(res.data) ? res.data : null;
  if (!m) {return JSON.stringify(res, null, 2);}
  const check = isRec(res.check) ? res.check : isRec(res.initialCheck) ? res.initialCheck : null;
  const parts: string[] = [formatMonitorSummaryLine(m)];
  if (check) {
    const condRes = isRec(check.conditionResult) ? check.conditionResult : null;
    if (condRes && str(condRes.summary)) {
      parts.push(`Condition: ${str(condRes.summary)} (met: ${Boolean(condRes.met)})`);
    }
    if (str(check.diffSummary)) {
      parts.push(`Summary: ${str(check.diffSummary)}`);
    }
  }
  const snap = (check && str(check.snapshot)) || str(m.lastSnapshot);
  if (snap) {
    parts.push(`Snapshot:\n${truncate(snap, 6_000)}`);
  }
  return parts.join("\n\n");
}
