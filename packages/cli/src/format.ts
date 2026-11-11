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

/** CVE records have no title/price; map them onto the shared row shape. */
const cveRow = (o: Rec): Rec => ({
  title: `${str(o.id)} ${str(o.title) || str(o.summary)}`.trim(),
  price: [str(o.cvssScore), str(o.severity), o.kev === true ? "KEV" : ""].filter(Boolean).join(" "),
  source: str(o.source),
  url: str(o.url),
});

const clip = (s: string, n: number) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

function rows(items: unknown[]): string {
  const data = items.filter(isRec).map((o) => ({
    title: clip(first(o, ["title", "name", "address", "airline", "productName"]) || "(untitled)", 52),
    price: first(o, ["priceText", "price", "pricePerNight", "minPrice"]),
    src: clip(first(o, ["provider", "portal", "vendor", "domain", "source"]), 24),
    url: first(o, ["url", "link"]),
  }));
  const w = (k: "title" | "price" | "src") => Math.max(...data.map((d) => d[k].length), 1);
  const [wt, wp, ws] = [w("title"), w("price"), w("src")];
  return data
    .map((d, i) => `${String(i + 1).padStart(2)}  ${d.title.padEnd(wt)}  ${d.price.padEnd(wp)}  ${d.src.padEnd(ws)}${d.url ? `\n    ${d.url}` : ""}`)
    .join("\n");
}

export function formatSearch(res: Rec): string {
  const parts: string[] = [];
  for (const key of VERTICALS) {
    const arr = res[key];
    if (Array.isArray(arr) && arr.length) {
      parts.push(`${key}\n${rows(key === "cves" ? arr.filter(isRec).map(cveRow) : arr)}`);
    }
  }
  const results = Array.isArray(res.results) ? res.results : Array.isArray(res.data) ? res.data : [];
  if (results.length) {
    parts.push(
      `results\n${results
        .filter(isRec)
        .map((r, i) => {
          const desc = first(r, ["description", "snippet"]).replace(/\s+/g, " ").slice(0, 160);
          return `${String(i + 1).padStart(2)}  ${first(r, ["title"]) || "(untitled)"}\n    ${first(r, ["url"])}${desc ? `\n    ${desc}` : ""}`;
        })
        .join("\n")}`
    );
  }
  if (parts.length) return parts.join("\n\n");
  if (res.success === false && str(res.error)) return `Error: ${str(res.error)}`;
  return "No results.";
}

export function formatScrape(res: Rec): string {
  if (res.success === false && str(res.error)) {return `Error: ${str(res.error)}`;}
  const d = isRec(res.data) ? res.data : res;
  return str(d.markdown) || str(d.content) || "(no content returned)";
}

export function formatMap(res: Rec): string {
  const links = Array.isArray(res.links) ? res.links : Array.isArray(res.urls) ? res.urls : [];
  return links.map((l) => (isRec(l) ? str(l.url) : str(l))).filter(Boolean).join("\n") || "No URLs found.";
}

export function formatCrawl(res: Rec): string {
  const pages = Array.isArray(res.data) ? res.data : Array.isArray(res.pages) ? res.pages : [];
  if (!pages.length) {return "No pages crawled.";}
  return pages
    .filter(isRec)
    .map((p) => {
      const url = str(p.url) || (isRec(p.metadata) ? str(p.metadata.sourceURL) || str(p.metadata.url) : "");
      return `# ${str(p.title) || url || "page"}\n${url}\n\n${str(p.markdown)}`;
    })
    .join("\n\n---\n\n");
}

export function formatRerank(res: Rec): string {
  const items = Array.isArray(res.results) ? res.results : Array.isArray(res.data) ? res.data : [];
  if (!items.length) {return JSON.stringify(res, null, 2);}
  return items
    .map((r, i) => {
      const o = isRec(r) ? r : {};
      const score = typeof o.score === "number" ? o.score.toFixed(3) : "";
      return `${String(i + 1).padStart(2)}  ${score.padEnd(6)}  ${clip(first(o, ["description", "markdown", "title"]).replace(/\s+/g, " "), 100)}`;
    })
    .join("\n");
}

export function formatCredits(res: Rec): string {
  const c = res.credits;
  if (!isRec(c)) {return "";}
  const bits = [
    typeof c.charged === "number" ? `charged ${c.charged}` : "",
    typeof c.remaining === "number" ? `${c.remaining} remaining` : "",
  ].filter(Boolean);
  return bits.join(", ");
}

export function formatTargets(res: Rec): string {
  const list = Array.isArray(res.targets) ? res.targets.filter(isRec) : [];
  if (!list.length) {return "No targets registered.";}
  return list
    .map((t) => {
      const id = str(t.id).padEnd(16);
      const name = str(t.name);
      const returns = str(t.returns);
      const reqs = str(t.requirements);
      return `${id}  ${name}\n                  Returns: ${returns}\n                  Requires: ${reqs}`;
    })
    .join("\n\n");
}

function formatMonitorItem(m: Rec, index?: number): string {
  const num = index !== undefined ? `${String(index + 1).padStart(2)}  ` : "";
  const id = str(m.id);
  const name = str(m.name) || str(m.url) || "(unnamed watch)";
  const status = str(m.status) || "active";
  const mode = str(m.mode) || "page";
  const urls = Array.isArray(m.urls) ? m.urls.map(str).filter(Boolean) : [];
  const scopeLabel =
    mode === "site"
      ? `site (max ${str(m.maxPages) || "5"} pages)`
      : mode === "urls"
        ? `${urls.length || 1} URLs`
        : "1 page";
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
  const pad = index !== undefined ? "    " : "";
  const diff = str(m.lastDiffSummary);
  return [
    `${num}${name}  [${id}]  (${meta})`,
    `${pad}${str(m.url)}${urls.length > 1 ? ` (+${urls.length - 1} more)` : ""}  ·  ${goal}`,
    diff ? `${pad}Latest: ${diff}` : "",
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
    return list.map((m, i) => formatMonitorItem(m, i)).join("\n\n");
  }
  const m = isRec(res.monitor) ? res.monitor : isRec(res.data) ? res.data : null;
  if (!m) {return JSON.stringify(res, null, 2);}
  const check = isRec(res.check) ? res.check : isRec(res.initialCheck) ? res.initialCheck : null;
  const lines = [formatMonitorItem(m)];
  if (check) {
    const condRes = isRec(check.conditionResult) ? check.conditionResult : null;
    if (condRes && str(condRes.summary)) {
      lines.push(`Condition: ${str(condRes.summary)} (met: ${Boolean(condRes.met)})`);
    }
    if (str(check.diffSummary)) {
      lines.push(`Summary: ${str(check.diffSummary)}`);
    }
  }
  const snap = (check && str(check.snapshot)) || str(m.lastSnapshot);
  if (snap) {
    lines.push(`\n${snap}`);
  }
  return lines.join("\n");
}
