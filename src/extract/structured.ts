/**
 * Prompt/schema-aware structured extraction used by `extractWebsiteData`.
 * Deterministic (no LLM): quote/author cards, embedded JSON, and schema shaping.
 *
 * Nested objects/arrays follow a JSON-schema walk: shorthand
 * `{items:[{quote,author}]}` is coerced to a real object/array schema,
 * root arrays are wrapped as `{items: ...}`, and empty results are detectable.
 */
import { decodeHtmlEntities } from "../engine/markdown.js";

export interface QuoteAuthor {
  text: string;
  author: string;
}

const CACHE_META_KEYS = new Set(["cached", "cacheLayer"]);

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

/** A bare property map or shorthand array becomes a JSON Schema. */
export function coerceExtractSchema(node: unknown): Record<string, unknown> {
  if (Array.isArray(node)) {
    const item = node.length > 0 ? coerceExtractSchema(node[0]) : { type: "object" };
    return { type: "array", items: item };
  }
  if (typeof node === "string") {
    const t = node.trim() || "string";
    return { type: t };
  }
  if (!isPlainObject(node)) {
    return { type: "string" };
  }
  if (typeof node.type === "string" || Array.isArray(node.type)) {
    const out: Record<string, unknown> = { ...node };
    if (isPlainObject(out.properties)) {
      out.properties = Object.fromEntries(
        Object.entries(out.properties).map(([k, v]) => [k, coerceExtractSchema(v)])
      );
    }
    if (out.items !== undefined) {
      out.items = coerceExtractSchema(out.items);
    }
    return out;
  }
  const properties = Object.fromEntries(
    Object.entries(node).map(([k, v]) => [k, coerceExtractSchema(v)])
  );
  return {
    type: "object",
    properties,
    required: Object.keys(properties),
    additionalProperties: false,
  };
}

/**
 * Root-array wrap: a top-level array becomes
 * `{ type: object, properties: { items: <array> } }`.
 */
export function normalizeExtractSchema(
  schema?: Record<string, unknown>
): Record<string, unknown> | undefined {
  if (!schema || typeof schema !== "object") return undefined;
  let coerced = coerceExtractSchema(schema);
  if (coerced.type === "array") {
    coerced = {
      type: "object",
      properties: { items: coerced },
      required: ["items"],
      additionalProperties: false,
    };
  }
  return coerced;
}

export function schemaProperties(schema?: Record<string, unknown>): Record<string, unknown> {
  const normalized = normalizeExtractSchema(schema);
  if (!normalized) return {};
  const props = normalized.properties;
  if (isPlainObject(props)) return props;
  return normalized;
}

export function hasCustomExtractRequest(
  prompt?: string,
  schema?: Record<string, unknown>
): boolean {
  if (prompt && prompt.trim()) return true;
  return Object.keys(schemaProperties(schema)).length > 0;
}

function blobForIntent(prompt?: string, schema?: Record<string, unknown>): string {
  const keys: string[] = [];
  const walk = (node: unknown) => {
    if (Array.isArray(node)) {
      for (const n of node) walk(n);
      return;
    }
    if (!isPlainObject(node)) return;
    keys.push(...Object.keys(node));
    if (isPlainObject(node.properties)) walk(node.properties);
    if (node.items) walk(node.items);
  };
  walk(schema);
  walk(schemaProperties(schema));
  return `${prompt ?? ""} ${keys.join(" ")}`.toLowerCase();
}

/** Nested object/array field names that look like quote+author records. */
export function nestedQuoteAuthorFields(
  schema?: Record<string, unknown>
): { arrayPath: string[]; textKey: string; authorKey: string } | null {
  const normalized = normalizeExtractSchema(schema);
  if (!normalized) return null;

  const visit = (
    node: Record<string, unknown>,
    path: string[]
  ): { arrayPath: string[]; textKey: string; authorKey: string } | null => {
    if (node.type === "array" && node.items) {
      const items = coerceExtractSchema(node.items);
      const itemProps = isPlainObject(items.properties) ? items.properties : {};
      const itemKeys = Object.keys(itemProps);
      const textKey = itemKeys.find((k) => /quote|text|content|body/i.test(k));
      const authorKey = itemKeys.find((k) => /author|by|name/i.test(k));
      if (textKey && authorKey) {
        return { arrayPath: path, textKey, authorKey };
      }
      if (items.type === "object" && isPlainObject(items.properties)) {
        const nested = visit(items, path);
        if (nested) return nested;
      }
    }
    const props = isPlainObject(node.properties) ? node.properties : {};
    for (const [key, value] of Object.entries(props)) {
      if (!isPlainObject(value) && !Array.isArray(value)) continue;
      const child = coerceExtractSchema(value);
      const found = visit(child, [...path, key]);
      if (found) return found;
    }
    return null;
  };

  return visit(normalized, []);
}

export function wantsQuoteAuthorExtract(prompt?: string, schema?: Record<string, unknown>): boolean {
  const blob = blobForIntent(prompt, schema);
  if (/\bquotes?\b/.test(blob) && /\bauthors?\b/.test(blob)) return true;
  const props = schemaProperties(schema);
  if (props.quotes || props.quote || props.authors) return true;
  if (nestedQuoteAuthorFields(schema)) return true;
  return false;
}

/** Strip script/style/template (including unclosed tags) before reading visible DOM. */
export function stripNonContentHtml(html: string): string {
  return String(html ?? "")
    .replace(/<!--[\s\S]*?-->/g, "")
    .replace(
      /<(script|style|noscript|svg|canvas|template|iframe)(?:[^>"']|"[^"]*"|'[^']*')*>[\s\S]*?<\/\1>/gi,
      ""
    )
    .replace(
      /<(script|style|noscript|svg|canvas|template|iframe)(?:[^>"']|"[^"]*"|'[^']*')*>[\s\S]*/gi,
      ""
    );
}

/** Inline `document.write("... " + d['text'] + ...)` leftovers, not real quotes. */
export function isJsTemplateJunk(text: string): boolean {
  const t = String(text ?? "");
  return (
    /\+\s*d\s*\[/i.test(t) ||
    /['"]\s*\+\s*d/i.test(t) ||
    /\bd\s*\[\s*['"]text['"]\s*\]/.test(t) ||
    /\bd\s*\[\s*['"]author['"]\s*\]/.test(t) ||
    /document\.write/i.test(t)
  );
}

export function isEmptyExtractResult(data: Record<string, unknown> | null | undefined): boolean {
  if (!data || typeof data !== "object") return true;
  const keys = Object.keys(data).filter((k) => !CACHE_META_KEYS.has(k));
  if (keys.length === 0) return true;
  return keys.every((k) => {
    const v = data[k];
    if (v == null || v === "") return true;
    if (Array.isArray(v)) return v.length === 0;
    if (typeof v === "object" && !Array.isArray(v)) {
      return isEmptyExtractResult(v as Record<string, unknown>);
    }
    return false;
  });
}

function cleanText(raw: string): string {
  return decodeHtmlEntities(raw.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim());
}

function pushPair(out: QuoteAuthor[], text: string, author: string): void {
  const t = cleanText(text).replace(/^["“]|["”]$/g, "").trim();
  const a = cleanText(author);
  if (t.length < 8 || a.length < 2) return;
  if (isJsTemplateJunk(t) || isJsTemplateJunk(a)) return;
  if (out.some((p) => p.text === t && p.author === a)) return;
  out.push({ text: t, author: a });
}

/** Pull quote/author pairs from HTML (cards, microdata, `var data = [...]`) and markdown. */
export function extractQuoteAuthorPairs(html: string, markdown = ""): QuoteAuthor[] {
  const out: QuoteAuthor[] = [];
  const source = String(html ?? "");

  const dataAssign = source.match(/var\s+data\s*=\s*(\[[\s\S]*?\]);/);
  if (dataAssign) {
    try {
      const parsed = JSON.parse(dataAssign[1]) as Array<{
        text?: string;
        author?: { name?: string } | string;
      }>;
      if (Array.isArray(parsed)) {
        for (const row of parsed) {
          const author =
            typeof row.author === "string" ? row.author : row.author?.name ?? "";
          if (row.text && author) pushPair(out, row.text, author);
        }
      }
    } catch {
      /* not JSON */
    }
  }

  const visible = stripNonContentHtml(source);

  const cardRe =
    /<(?:div|figure|blockquote|li)[^>]*class=["'][^"']*\bquote\b[^"']*["'][^>]*>([\s\S]*?)<\/(?:div|figure|blockquote|li)>/gi;
  let card: RegExpExecArray | null;
  while ((card = cardRe.exec(visible)) !== null) {
    const block = card[1];
    const text =
      block.match(/<(?:span|div|p|q)[^>]*class=["'][^"']*\btext\b[^"']*["'][^>]*>([\s\S]*?)<\//i)?.[1] ||
      block.match(/itemprop=["']text["'][^>]*>([\s\S]*?)<\//i)?.[1] ||
      "";
    const author =
      block.match(/<(?:small|span|div|p)[^>]*class=["'][^"']*\bauthor\b[^"']*["'][^>]*>([\s\S]*?)<\//i)?.[1] ||
      block.match(/itemprop=["']author["'][^>]*>([\s\S]*?)<\//i)?.[1] ||
      "";
    if (text && author) pushPair(out, text, author);
  }

  const microRe =
    /itemprop=["']text["'][^>]*>([\s\S]*?)<\/[^>]+>[\s\S]{0,400}?itemprop=["']author["'][^>]*>([\s\S]*?)<\//gi;
  let micro: RegExpExecArray | null;
  while ((micro = microRe.exec(visible)) !== null) {
    pushPair(out, micro[1], micro[2]);
  }

  if (out.length === 0 && markdown) {
    const mdRe = /[“"]([^”"]{12,400})[”"]\s*(?:\n+)?\s*(?:by\s+|\u2014\s*|\s+[-–—]\s+)([A-Z][^\n]{1,80})/g;
    let md: RegExpExecArray | null;
    while ((md = mdRe.exec(markdown)) !== null) {
      pushPair(out, md[1], md[2]);
    }
  }

  return out;
}

function itemFieldNames(schema?: Record<string, unknown>): {
  arrayKey: string;
  textKey: string;
  authorKey: string;
} {
  const nested = nestedQuoteAuthorFields(schema);
  if (nested && nested.arrayPath.length > 0) {
    return {
      arrayKey: nested.arrayPath[nested.arrayPath.length - 1] || "items",
      textKey: nested.textKey,
      authorKey: nested.authorKey,
    };
  }
  const props = schemaProperties(schema);
  const keys = Object.keys(props);
  const arrayKey =
    keys.find((k) => {
      const p = props[k];
      if (!p || typeof p !== "object") return /quotes?|items|results|entries/i.test(k);
      const t = (p as { type?: unknown }).type;
      return t === "array" || /quotes?|items|results|entries/i.test(k);
    }) || (keys.length === 0 ? "quotes" : undefined);
  const itemSchema =
    arrayKey && props[arrayKey] && typeof props[arrayKey] === "object"
      ? (props[arrayKey] as { items?: { properties?: Record<string, unknown> } })
      : undefined;
  const itemProps = itemSchema?.items?.properties ?? {};
  const itemKeys = Object.keys(itemProps);
  const textKey = itemKeys.find((k) => /quote|text|content|body/i.test(k)) ?? "quote";
  const authorKey = itemKeys.find((k) => /author|by|name/i.test(k)) ?? "author";
  return { arrayKey: arrayKey ?? "quotes", textKey, authorKey };
}

function assignAtPath(
  root: Record<string, unknown>,
  path: string[],
  value: unknown
): Record<string, unknown> {
  if (path.length === 0) {
    return isPlainObject(value) ? { ...root, ...value } : root;
  }
  let cursor = root;
  for (let i = 0; i < path.length - 1; i++) {
    const key = path[i];
    const next = cursor[key];
    if (!isPlainObject(next)) {
      cursor[key] = {};
    }
    cursor = cursor[key] as Record<string, unknown>;
  }
  cursor[path[path.length - 1]] = value;
  return root;
}

export function shapeQuoteAuthors(
  pairs: QuoteAuthor[],
  schema?: Record<string, unknown>
): Record<string, unknown> {
  const props = schemaProperties(schema);
  const keys = Object.keys(props);
  const quoteArr = keys.find((k) => /quotes?/i.test(k) && (props[k] as { type?: string })?.type === "array");
  const authorArr = keys.find((k) => /authors?/i.test(k) && (props[k] as { type?: string })?.type === "array");
  const quoteArrItems = quoteArr && (props[quoteArr] as { items?: { type?: string } })?.items?.type;
  if (quoteArr && authorArr && quoteArrItems === "string") {
    return {
      [quoteArr]: pairs.map((p) => p.text),
      [authorArr]: pairs.map((p) => p.author),
    };
  }
  const nested = nestedQuoteAuthorFields(schema);
  const { arrayKey, textKey, authorKey } = itemFieldNames(schema);
  const rows = pairs.map((p) => ({ [textKey]: p.text, [authorKey]: p.author }));
  if (nested && nested.arrayPath.length > 0) {
    return assignAtPath({}, nested.arrayPath, rows);
  }
  return { [arrayKey]: rows };
}

/**
 * Deterministic extract when the caller passed a prompt and/or JSON schema.
 * Returns null when this page/request has nothing this extractor can fill.
 */
export function extractByPromptAndSchema(
  html: string,
  markdown: string,
  prompt?: string,
  schema?: Record<string, unknown>
): Record<string, unknown> | null {
  if (!hasCustomExtractRequest(prompt, schema)) return null;
  const pairs = extractQuoteAuthorPairs(html, markdown);
  if (wantsQuoteAuthorExtract(prompt, schema) && pairs.length > 0) {
    return shapeQuoteAuthors(pairs, schema);
  }
  if (pairs.length > 0 && /\b(quotes?|items|results|entries)\b/i.test(blobForIntent(prompt, schema))) {
    return shapeQuoteAuthors(pairs, schema);
  }
  return null;
}
