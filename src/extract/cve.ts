// Structured CVE records for the `security` search category.
// Sources: NVD CVE API 2.0 (scores, CWE, CPE products, KEV flag) and OSV
// (ecosystem package ranges and fixed versions, GHSA <-> CVE aliases).

export type CveSeverity = "critical" | "high" | "medium" | "low" | "none";

export interface CveAffected {
  vendor?: string;
  product: string;
  ecosystem?: string;
  /** Human range, e.g. ">=5.6.0 <5.6.2" or "5.6.0, 5.6.1" */
  versions?: string;
  fixed?: string;
}

export interface CveRecord {
  id: string;
  aliases?: string[];
  title?: string;
  summary: string;
  severity?: CveSeverity;
  /** 0-10, highest available of CVSS v4.0 / v3.1 / v3.0 / v2.0 */
  cvssScore?: number;
  cvssVector?: string;
  cvssVersion?: "4.0" | "3.1" | "3.0" | "2.0";
  cwe?: string[];
  affected?: CveAffected[];
  published?: string;
  modified?: string;
  /** Listed in CISA's Known Exploited Vulnerabilities catalog */
  kev?: boolean;
  references: string[];
  url: string;
  source: "nvd" | "osv" | "page";
}

const CVE_RE = /\bCVE-(\d{4})-(\d{4,7})\b/gi;
const GHSA_RE = /\bGHSA(?:-[23456789cfghjmpqrvwx]{4}){3}\b/gi;

export const SEVERITY_ORDER: Record<CveSeverity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  none: 0,
};

const roundUp1 = (x: number) => {
  const i = Math.round(x * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
};

/** CVSS v3.0/v3.1 base score from a vector string (FIRST spec). Undefined for v4 or malformed vectors. */
export function cvss3BaseScore(vector: string): number | undefined {
  if (!/^CVSS:3\.[01]\//.test(vector)) return undefined;
  const m = Object.fromEntries(
    vector.split("/").slice(1).map((p) => p.split(":") as [string, string])
  );
  const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[m.AV as "N"];
  const AC = { L: 0.77, H: 0.44 }[m.AC as "L"];
  const UI = { N: 0.85, R: 0.62 }[m.UI as "N"];
  const changed = m.S === "C";
  const PR = (changed ? { N: 0.85, L: 0.68, H: 0.5 } : { N: 0.85, L: 0.62, H: 0.27 })[m.PR as "N"];
  const cia = { H: 0.56, L: 0.22, N: 0 };
  const C = cia[m.C as "H"];
  const I = cia[m.I as "H"];
  const A = cia[m.A as "H"];
  if ([AV, AC, UI, PR, C, I, A].some((v) => v === undefined) || (m.S !== "U" && m.S !== "C")) return undefined;
  const iss = 1 - (1 - C) * (1 - I) * (1 - A);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  if (impact <= 0) return 0;
  const exploitability = 8.22 * AV * AC * PR * UI;
  return changed
    ? roundUp1(Math.min(1.08 * (impact + exploitability), 10))
    : roundUp1(Math.min(impact + exploitability, 10));
}

/** CVSS v3/v4 qualitative rating bands. */
export function severityFromScore(score: number | undefined): CveSeverity | undefined {
  if (score === undefined || !Number.isFinite(score)) return undefined;
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score > 0) return "low";
  return "none";
}

function normalizeSeverity(raw: unknown): CveSeverity | undefined {
  const s = String(raw ?? "").trim().toLowerCase();
  if (s === "critical") return "critical";
  if (s === "high" || s === "important") return "high";
  if (s === "medium" || s === "moderate") return "medium";
  if (s === "low") return "low";
  if (s === "none") return "none";
  return undefined;
}

export function normalizeCveId(id: string): string {
  return id.trim().toUpperCase();
}

/** Unique CVE ids in order of first appearance. */
export function extractCveIdsFromText(text: string, max = 20): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const m of text.matchAll(CVE_RE)) {
    const id = normalizeCveId(m[0]);
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(id);
    if (out.length >= max) break;
  }
  return out;
}

export function extractGhsaIdsFromText(text: string, max = 10): string[] {
  const out = new Set<string>();
  for (const m of text.matchAll(GHSA_RE)) {
    out.add(`GHSA${m[0].slice(4).toLowerCase()}`);
    if (out.size >= max) break;
  }
  return [...out];
}

export function looksLikeVulnId(query: string): boolean {
  return /\bCVE-\d{4}-\d{4,7}\b/i.test(query) || /\bGHSA(?:-[a-z0-9]{4}){3}\b/i.test(query);
}

export const nvdUrl = (id: string) => `https://nvd.nist.gov/vuln/detail/${id}`;

type Json = Record<string, any>;

function englishDescription(list: unknown): string {
  if (!Array.isArray(list)) return "";
  const en = list.find((d: Json) => d?.lang === "en") ?? list[0];
  return String(en?.value ?? "").replace(/\s+/g, " ").trim();
}

function pickNvdCvss(metrics: Json | undefined): Pick<CveRecord, "cvssScore" | "cvssVector" | "cvssVersion" | "severity"> {
  if (!metrics) return {};
  const order: Array<[string, CveRecord["cvssVersion"]]> = [
    ["cvssMetricV40", "4.0"],
    ["cvssMetricV31", "3.1"],
    ["cvssMetricV30", "3.0"],
    ["cvssMetricV2", "2.0"],
  ];
  for (const [key, version] of order) {
    const list = metrics[key];
    if (!Array.isArray(list) || list.length === 0) continue;
    // Prefer NVD's own ("Primary") assessment over a CNA's secondary one.
    const m = list.find((x: Json) => x?.type === "Primary") ?? list[0];
    const data = m?.cvssData ?? {};
    const score = typeof data.baseScore === "number" ? data.baseScore : undefined;
    return {
      cvssScore: score,
      cvssVector: data.vectorString,
      cvssVersion: version,
      severity: normalizeSeverity(data.baseSeverity ?? m?.baseSeverity) ?? severityFromScore(score),
    };
  }
  return {};
}

function rangeText(m: Json): string | undefined {
  const parts: string[] = [];
  if (m.versionStartIncluding) parts.push(`>=${m.versionStartIncluding}`);
  if (m.versionStartExcluding) parts.push(`>${m.versionStartExcluding}`);
  if (m.versionEndIncluding) parts.push(`<=${m.versionEndIncluding}`);
  if (m.versionEndExcluding) parts.push(`<${m.versionEndExcluding}`);
  return parts.length ? parts.join(" ") : undefined;
}

function nvdAffected(configurations: unknown): CveAffected[] {
  if (!Array.isArray(configurations)) return [];
  const byKey = new Map<string, CveAffected & { _versions: string[] }>();
  const walk = (nodes: unknown) => {
    if (!Array.isArray(nodes)) return;
    for (const node of nodes as Json[]) {
      for (const m of (node?.cpeMatch ?? []) as Json[]) {
        if (!m?.vulnerable || typeof m.criteria !== "string") continue;
        // cpe:2.3:<part>:<vendor>:<product>:<version>:...
        const [, , , vendor, product, version] = m.criteria.split(":");
        if (!product || product === "*") continue;
        const key = `${vendor}:${product}`;
        const entry =
          byKey.get(key) ??
          ({ vendor: vendor && vendor !== "*" ? vendor : undefined, product, _versions: [] } as CveAffected & {
            _versions: string[];
          });
        const range = rangeText(m) ?? (version && version !== "*" && version !== "-" ? version : undefined);
        if (range && !entry._versions.includes(range)) entry._versions.push(range);
        if (m.versionEndExcluding && !entry.fixed) entry.fixed = m.versionEndExcluding;
        byKey.set(key, entry);
      }
      walk(node?.children);
    }
  };
  for (const c of configurations as Json[]) walk(c?.nodes);
  return [...byKey.values()].slice(0, 8).map(({ _versions, ...a }) => ({
    ...a,
    ...(_versions.length ? { versions: _versions.slice(0, 4).join(", ") } : {}),
  }));
}

/** One NVD `vulnerabilities[].cve` object (or the wrapper) -> CveRecord. */
export function parseNvdCve(input: Json): CveRecord | null {
  const cve: Json | undefined = input?.cve ?? input;
  if (!cve || typeof cve.id !== "string") return null;
  const id = normalizeCveId(cve.id);
  if (!/^CVE-\d{4}-\d{4,}$/.test(id)) return null;
  const summary = englishDescription(cve.descriptions);
  const cwe = new Set<string>();
  for (const w of (cve.weaknesses ?? []) as Json[]) {
    for (const d of (w?.description ?? []) as Json[]) {
      const v = String(d?.value ?? "");
      if (/^CWE-\d+$/.test(v)) cwe.add(v);
    }
  }
  const affected = nvdAffected(cve.configurations);
  const refs = ((cve.references ?? []) as Json[])
    .map((r) => r?.url)
    .filter((u): u is string => typeof u === "string" && /^https?:\/\//.test(u));
  return {
    id,
    ...(cve.cisaVulnerabilityName ? { title: String(cve.cisaVulnerabilityName) } : {}),
    summary,
    ...pickNvdCvss(cve.metrics),
    ...(cwe.size ? { cwe: [...cwe] } : {}),
    ...(affected.length ? { affected } : {}),
    ...(cve.published ? { published: toIso(cve.published) } : {}),
    ...(cve.lastModified ? { modified: toIso(cve.lastModified) } : {}),
    ...(cve.cisaExploitAdd ? { kev: true } : {}),
    references: [...new Set(refs)].slice(0, 12),
    url: nvdUrl(id),
    source: "nvd",
  };
}

/** NVD 2.0 response body -> records. */
export function parseNvdResponse(body: Json): CveRecord[] {
  const list = Array.isArray(body?.vulnerabilities) ? body.vulnerabilities : [];
  return list.map(parseNvdCve).filter((r: CveRecord | null): r is CveRecord => r !== null);
}

function toIso(s: string): string {
  // NVD omits the zone ("2024-03-29T17:15:21.150"); treat as UTC.
  const withZone = /[zZ]|[+-]\d\d:?\d\d$/.test(s) ? s : `${s}Z`;
  const d = new Date(withZone);
  return Number.isNaN(d.getTime()) ? s : d.toISOString();
}

function osvAffected(affected: unknown): CveAffected[] {
  if (!Array.isArray(affected)) return [];
  const out: CveAffected[] = [];
  for (const a of affected as Json[]) {
    const name = a?.package?.name;
    if (typeof name !== "string" || !name) continue;
    const ranges: string[] = [];
    let fixed: string | undefined;
    for (const r of (a.ranges ?? []) as Json[]) {
      if (r?.type === "GIT") continue;
      let intro: string | undefined;
      for (const e of (r?.events ?? []) as Json[]) {
        if (e.introduced !== undefined) intro = String(e.introduced);
        if (e.fixed !== undefined) {
          fixed ??= String(e.fixed);
          ranges.push(intro && intro !== "0" ? `>=${intro} <${e.fixed}` : `<${e.fixed}`);
          intro = undefined;
        }
        if (e.last_affected !== undefined) {
          ranges.push(intro && intro !== "0" ? `>=${intro} <=${e.last_affected}` : `<=${e.last_affected}`);
          intro = undefined;
        }
      }
      if (intro !== undefined) ranges.push(intro === "0" ? "all versions" : `>=${intro}`);
    }
    if (!ranges.length && Array.isArray(a.versions) && a.versions.length) {
      ranges.push(a.versions.slice(0, 4).join(", ") + (a.versions.length > 4 ? ", …" : ""));
    }
    out.push({
      product: name,
      ...(a.package.ecosystem ? { ecosystem: String(a.package.ecosystem) } : {}),
      ...(ranges.length ? { versions: [...new Set(ranges)].slice(0, 4).join(", ") } : {}),
      ...(fixed ? { fixed } : {}),
    });
  }
  return out.slice(0, 8);
}

/** One OSV vulnerability object -> CveRecord, keyed by its CVE alias when it has one. */
export function parseOsvVuln(v: Json): CveRecord | null {
  if (typeof v?.id !== "string") return null;
  const ids = [v.id, ...(Array.isArray(v.aliases) ? v.aliases : [])].map(String);
  const cveId = ids.find((x) => /^CVE-\d{4}-\d{4,}$/i.test(x));
  const id = cveId ? normalizeCveId(cveId) : v.id;
  const aliases = [...new Set(ids.filter((x) => normalizeCveId(x) !== normalizeCveId(id)))];
  const vector = ((v.severity ?? []) as Json[]).find((s) => /^CVSS_V[34]/.test(s?.type))?.score;
  const sevRaw = v.database_specific?.severity ?? v.affected?.[0]?.database_specific?.severity;
  const cweIds = v.database_specific?.cwe_ids;
  const affected = osvAffected(v.affected);
  const refs = ((v.references ?? []) as Json[])
    .map((r) => r?.url)
    .filter((u): u is string => typeof u === "string" && /^https?:\/\//.test(u));
  const summary = String(v.summary || v.details || "").replace(/\s+/g, " ").trim();
  const score = typeof vector === "string" ? cvss3BaseScore(vector) : undefined;
  return {
    id,
    ...(aliases.length ? { aliases } : {}),
    ...(v.summary && v.details ? { title: String(v.summary) } : {}),
    summary: summary.length > 600 ? `${summary.slice(0, 597)}…` : summary,
    ...(score !== undefined ? { cvssScore: score } : {}),
    ...(normalizeSeverity(sevRaw) || severityFromScore(score)
      ? { severity: normalizeSeverity(sevRaw) ?? severityFromScore(score) }
      : {}),
    ...(typeof vector === "string"
      ? { cvssVector: vector, cvssVersion: vector.startsWith("CVSS:4.0") ? "4.0" : vector.startsWith("CVSS:3.0") ? "3.0" : "3.1" }
      : {}),
    ...(Array.isArray(cweIds) && cweIds.length ? { cwe: cweIds.map(String) } : {}),
    ...(affected.length ? { affected } : {}),
    ...(v.published ? { published: toIso(v.published) } : {}),
    ...(v.modified ? { modified: toIso(v.modified) } : {}),
    references: [...new Set(refs)].slice(0, 12),
    url: cveId ? nvdUrl(id) : `https://osv.dev/vulnerability/${v.id}`,
    source: "osv",
  } as CveRecord;
}

/**
 * Merge records for the same vulnerability across sources (matched on id or any alias).
 * NVD wins for scores, CWE and KEV; OSV fills ecosystem packages and fixed versions.
 */
export function mergeCveRecords(records: CveRecord[], max = 25): CveRecord[] {
  const byKey = new Map<string, CveRecord>();
  const keyOf = new Map<string, string>();
  const rank = (r: CveRecord) => (r.source === "nvd" ? 0 : r.source === "osv" ? 1 : 2);

  for (const rec of [...records].sort((a, b) => rank(a) - rank(b))) {
    const names = [rec.id, ...(rec.aliases ?? [])].map(normalizeCveId);
    const existingKey = names.map((n) => keyOf.get(n)).find(Boolean);
    if (!existingKey) {
      byKey.set(rec.id, { ...rec });
      for (const n of names) keyOf.set(n, rec.id);
      continue;
    }
    const cur = byKey.get(existingKey)!;
    const aliasMap = new Map<string, string>();
    for (const a of [...(cur.aliases ?? []), rec.id, ...(rec.aliases ?? [])]) {
      const n = normalizeCveId(a);
      if (n !== normalizeCveId(cur.id) && !aliasMap.has(n)) aliasMap.set(n, a);
    }
    const aliases = new Set(aliasMap.values());
    const affected = [...(cur.affected ?? [])];
    for (const a of rec.affected ?? []) {
      const match = affected.find((x) => x.product.toLowerCase() === a.product.toLowerCase());
      if (!match) affected.push(a);
      else {
        match.ecosystem ??= a.ecosystem;
        match.fixed ??= a.fixed;
        match.versions ??= a.versions;
      }
    }
    byKey.set(existingKey, {
      ...cur,
      aliases: aliases.size ? [...aliases] : undefined,
      title: cur.title ?? rec.title,
      summary: cur.summary || rec.summary,
      severity: cur.severity ?? rec.severity,
      cvssScore: cur.cvssScore ?? rec.cvssScore,
      cvssVector: cur.cvssVector ?? rec.cvssVector,
      cvssVersion: cur.cvssVersion ?? rec.cvssVersion,
      cwe: cur.cwe ?? rec.cwe,
      affected: affected.length ? affected.slice(0, 8) : undefined,
      published: cur.published ?? rec.published,
      modified: cur.modified ?? rec.modified,
      kev: cur.kev || rec.kev || undefined,
      references: [...new Set([...cur.references, ...rec.references])].slice(0, 16),
    });
    for (const n of names) keyOf.set(n, existingKey);
  }

  const out = [...byKey.values()].map((r) => {
    const clean = Object.fromEntries(Object.entries(r).filter(([, v]) => v !== undefined)) as unknown as CveRecord;
    if (!clean.severity && clean.cvssScore !== undefined) clean.severity = severityFromScore(clean.cvssScore);
    return clean;
  });
  return sortCveRecords(out).slice(0, max);
}

/** Exact-id hits first, then KEV, then severity, then newest. */
export function sortCveRecords(records: CveRecord[], pinnedIds: string[] = []): CveRecord[] {
  const pinned = new Set(pinnedIds.map(normalizeCveId));
  const isPinned = (r: CveRecord) => pinned.has(r.id) || (r.aliases ?? []).some((a) => pinned.has(normalizeCveId(a)));
  return [...records].sort((a, b) => {
    const p = Number(isPinned(b)) - Number(isPinned(a));
    if (p) return p;
    const k = Number(!!b.kev) - Number(!!a.kev);
    if (k) return k;
    const s = SEVERITY_ORDER[b.severity ?? "none"] - SEVERITY_ORDER[a.severity ?? "none"];
    if (s) return s;
    const sc = (b.cvssScore ?? -1) - (a.cvssScore ?? -1);
    if (sc) return sc;
    return (b.published ?? "").localeCompare(a.published ?? "");
  });
}

/** "9.8 Critical" / "High" for cards and MCP text. */
export function cveSeverityLabel(r: Pick<CveRecord, "cvssScore" | "severity">): string | undefined {
  const sev = r.severity ?? severityFromScore(r.cvssScore);
  const word = sev ? sev[0].toUpperCase() + sev.slice(1) : undefined;
  if (r.cvssScore !== undefined && word) return `${r.cvssScore.toFixed(1)} ${word}`;
  return word;
}
