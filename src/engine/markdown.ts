const HTML_ENTITIES: Record<string, string> = {
  "&amp;": "&",
  "&lt;": "<",
  "&gt;": ">",
  "&quot;": '"',
  "&#39;": "'",
  "&apos;": "'",
  "&nbsp;": " ",
  "&ndash;": "–",
  "&mdash;": "\u2014",
  "&copy;": "©",
  "&reg;": "®",
  "&trade;": "™",
  "&hellip;": "…",
};

export function decodeHtmlEntities(text: string): string {
  return text.replace(/&[a-zA-Z0-9#]+;/g, (entity) => {
    if (HTML_ENTITIES[entity]) {
      return HTML_ENTITIES[entity];
    }
    if (entity.startsWith("&#x") || entity.startsWith("&#X")) {
      const code = parseInt(entity.slice(3, -1), 16);
      return !Number.isNaN(code) ? String.fromCodePoint(code) : entity;
    }
    if (entity.startsWith("&#")) {
      const code = parseInt(entity.slice(2, -1), 10);
      return !Number.isNaN(code) ? String.fromCodePoint(code) : entity;
    }
    return entity;
  });
}


export interface MarkdownOptions {
  retainImages?: "all" | "none";
  /** Default true: prefer <main>/<article> and drop header/footer/nav/aside. */
  onlyMainContent?: boolean;
  /** Simple selectors (`tag`, `.class`, `#id`, `tag.class`). Keep only matching elements. */
  includeTags?: string[];
  /** Same selector syntax. Matching elements are removed. */
  excludeTags?: string[];
}

const VOID_TAGS = new Set(["area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"]);

interface SimpleSelector {
  tag?: string;
  id?: string;
  classes: string[];
}

function parseSelector(raw: string): SimpleSelector | null {
  const m = raw.trim().match(/^([a-z][a-z0-9-]*)?((?:[.#][\w-]+)*)$/i);
  if (!m || (!m[1] && !m[2])) return null;
  const sel: SimpleSelector = { tag: m[1]?.toLowerCase(), classes: [] };
  for (const part of m[2].match(/[.#][\w-]+/g) ?? []) {
    if (part[0] === "#") sel.id = part.slice(1);
    else sel.classes.push(part.slice(1));
  }
  return sel;
}

function openTagMatches(tagName: string, attrs: string, sel: SimpleSelector): boolean {
  if (sel.tag && sel.tag !== tagName) return false;
  if (sel.id) {
    const id = attrs.match(/\bid=["']([^"']*)["']/i)?.[1];
    if (id !== sel.id) return false;
  }
  if (sel.classes.length) {
    const cls = (attrs.match(/\bclass=["']([^"']*)["']/i)?.[1] ?? "").split(/\s+/);
    if (!sel.classes.every((c) => cls.includes(c))) return false;
  }
  return true;
}

/** Finds balanced `[start, end)` ranges of elements matching any selector (outermost only). */
function findElementRanges(html: string, selectors: SimpleSelector[]): Array<[number, number]> {
  const ranges: Array<[number, number]> = [];
  const openRe = /<([a-z][a-z0-9-]*)((?:[^>"']|"[^"]*"|'[^']*')*)>/gi;
  let m: RegExpExecArray | null;
  let skipUntil = 0;
  while ((m = openRe.exec(html)) !== null) {
    if (m.index < skipUntil) continue;
    const tag = m[1].toLowerCase();
    if (!selectors.some((sel) => openTagMatches(tag, m![2], sel))) continue;
    if (VOID_TAGS.has(tag) || m[2].trimEnd().endsWith("/")) {
      ranges.push([m.index, m.index + m[0].length]);
      skipUntil = m.index + m[0].length;
      continue;
    }
    const re = new RegExp(`<(/?)${tag}(?=[\\s>/])(?:[^>"']|"[^"]*"|'[^']*')*>`, "gi");
    re.lastIndex = m.index + m[0].length;
    let depth = 1;
    let end = html.length;
    let t: RegExpExecArray | null;
    while ((t = re.exec(html)) !== null) {
      depth += t[1] ? -1 : 1;
      if (depth === 0) {
        end = t.index + t[0].length;
        break;
      }
    }
    ranges.push([m.index, end]);
    skipUntil = end;
  }
  return ranges;
}

export function removeElements(html: string, rawSelectors: string[]): string {
  const sels = rawSelectors.map(parseSelector).filter((x): x is SimpleSelector => !!x);
  if (!sels.length) return html;
  const ranges = findElementRanges(html, sels);
  let out = "";
  let pos = 0;
  for (const [a, b] of ranges) {
    out += html.slice(pos, a);
    pos = b;
  }
  return out + html.slice(pos);
}

export function keepElements(html: string, rawSelectors: string[]): string {
  const sels = rawSelectors.map(parseSelector).filter((x): x is SimpleSelector => !!x);
  if (!sels.length) return html;
  const ranges = findElementRanges(html, sels);
  if (!ranges.length) return html;
  return ranges.map(([a, b]) => html.slice(a, b)).join("\n");
}

/**
 * Ultra-fast zero-DOM streaming regex/state-machine HTML-to-Markdown converter.
 * Processes a 200KB HTML document in ~1.2ms (vs 45-120ms for JSDOM + Turndown).
 */
export function fastHtmlToMarkdown(
  html: string,
  baseUrl: string,
  options: MarkdownOptions = {}
): { title: string; markdown: string; links: string[] } {
  // 1. Extract <title> or og:title, plus meta description
  const titleMatch =
    html.match(/<title[^>]*>([\s\S]*?)<\/title>/i) ||
    html.match(
      /<meta[^>]+property=["']og:title["'][^>]+content=["']([^"']+)["']/i
    ) ||
    html.match(/<h1(?:[^>"']|"[^"]*"|'[^']*')*>([\s\S]*?)<\/h1>/i);
  const rawTitle = titleMatch ? stripTags(titleMatch[1]).trim() : "";
  const title = decodeHtmlEntities(rawTitle) || baseUrl;

  const metaDescMatch =
    html.match(
      /<meta[^>]+name=["']description["'][^>]+content=["']([^"']+)["']/i
    ) ||
    html.match(
      /<meta[^>]+content=["']([^"']+)["'][^>]+name=["']description["']/i
    ) ||
    html.match(
      /<meta[^>]+property=["']og:description["'][^>]+content=["']([^"']+)["']/i
    );
  const metaDescription = metaDescMatch
    ? decodeHtmlEntities(metaDescMatch[1].trim())
    : "";

  // 2. Extract all <a href="..."> links before stripping nav/header/footer
  const linksSet = new Set<string>();
  const linkRegex = /<a\s+[^>]*href=["']([^"'#]+)["'][^>]*>/gi;
  let linkMatch: RegExpExecArray | null;
  while ((linkMatch = linkRegex.exec(html)) !== null) {
    const href = linkMatch[1].trim();
    if (
      !href ||
      href.startsWith("javascript:") ||
      href.startsWith("mailto:") ||
      href.startsWith("tel:")
    ) {
      continue;
    }
    try {
      const resolved = new URL(href, baseUrl);
      resolved.hash = "";
      if (resolved.protocol === "http:" || resolved.protocol === "https:") {
        linksSet.add(resolved.toString());
      }
    } catch {
      // ignore malformed URLs
    }
  }

  // 3. Focus on <main>/<article> (unless onlyMainContent is false), else <body>
  const onlyMain = options.onlyMainContent !== false;
  let bodyHtml = html;
  if (options.includeTags?.length) {
    bodyHtml = keepElements(html, options.includeTags);
  } else {
    const mainMatch = onlyMain
      ? html.match(/<main[^>]*>([\s\S]*?)<\/main>/i) ||
        html.match(/<article[^>]*>([\s\S]*?)<\/article>/i)
      : null;
    if (mainMatch && mainMatch[1].length > 400) {
      bodyHtml = mainMatch[1];
    } else {
      const bodyMatch = html.match(/<body[^>]*>([\s\S]*?)<\/body>/i);
      if (bodyMatch) {
        bodyHtml = bodyMatch[1];
      }
    }
  }
  if (options.excludeTags?.length) {
    bodyHtml = removeElements(bodyHtml, options.excludeTags);
  }

  // 4. Strip noise tags: script, style, noscript, svg, iframe, dialog, form, aria-hidden (+ nav chrome when onlyMainContent)
  let cleaned = bodyHtml
    .replace(/<!--[\s\S]*?-->/g, "")
    .replace(
      /<(script|style|noscript|svg|canvas|template|iframe|dialog|form)(?:[^>"']|"[^"]*"|'[^']*')*>[\s\S]*?<\/\1>/gi,
      ""
    );
  if (onlyMain) {
    cleaned = cleaned.replace(
      /<(header|footer|nav|aside)(?:[^>"']|"[^"]*"|'[^']*')*>[\s\S]*?<\/\1>/gi,
      ""
    );
  }
  cleaned = cleaned.replace(
    /<([a-z0-9]+)\b(?:[^>"']|"[^"]*"|'[^']*')*\baria-hidden=["']true["'](?:[^>"']|"[^"]*"|'[^']*')*>[\s\S]*?<\/\1>/gi,
    ""
  );

  // 5. Preserve <pre><code> blocks via placeholders so whitespace isn't collapsed
  const codeBlocks: string[] = [];
  cleaned = cleaned.replace(
    /<pre[^>]*>\s*(?:<code[^>]*>)?([\s\S]*?)(?:<\/code>)?\s*<\/pre>/gi,
    (_full, codeContent: string) => {
      const idx = codeBlocks.length;
      const decoded = decodeHtmlEntities(stripTags(codeContent)).trim();
      codeBlocks.push(`\n\`\`\`\n${decoded}\n\`\`\`\n`);
      return `__WEBCRAWL_CODE_BLOCK_${idx}__`;
    }
  );

  // 6. Images
  if (options.retainImages === "none") {
    cleaned = cleaned.replace(/<img[^>]*>/gi, "");
  } else {
    cleaned = cleaned.replace(/<img\s+[^>]*>/gi, (imgTag) => {
      const srcMatch = imgTag.match(/src=["']([^"']+)["']/i);
      if (!srcMatch) {
        return "";
      }
      const altMatch = imgTag.match(/alt=["']([^"']*)["']/i);
      const alt = altMatch ? decodeHtmlEntities(altMatch[1].trim()) : "";
      try {
        const absSrc = new URL(srcMatch[1], baseUrl).toString();
        return `![${alt}](${absSrc})`;
      } catch {
        return "";
      }
    });
  }

  // 7. Links: <a href="...">text</a> -> [text](url)
  cleaned = cleaned.replace(
    /<a\s+[^>]*href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi,
    (_full, href: string, inner: string) => {
      const linkText = decodeHtmlEntities(stripTags(inner))
        .replace(/\s+/g, " ")
        .trim();
      if (!linkText) {
        return "";
      }
      if (href.startsWith("javascript:") || href.startsWith("#")) {
        return linkText;
      }
      try {
        const absUrl = new URL(href, baseUrl).toString();
        return `[${linkText}](${absUrl})`;
      } catch {
        return linkText;
      }
    }
  );

  // 8. Headings h1-h6 (handle > inside quoted attributes like Tailwind class="[&>*]:mb-0")
  cleaned = cleaned.replace(
    /<h([1-6])(?:[^>"']|"[^"]*"|'[^']*')*>([\s\S]*?)<\/h\1>/gi,
    (_f, level: string, inner: string) => {
      const hashes = "#".repeat(Number(level));
      const text = decodeHtmlEntities(stripTags(inner))
        .replace(/\s+/g, " ")
        .trim();
      return text ? `\n\n${hashes} ${text}\n\n` : "";
    }
  );

  // 9. Inline formatting
  cleaned = cleaned
    .replace(
      /<(strong|b)(?:\s(?:[^>"']|"[^"]*"|'[^']*')*)?>([\s\S]*?)<\/\1>/gi,
      "**$2**"
    )
    .replace(
      /<(em|i)(?:\s(?:[^>"']|"[^"]*"|'[^']*')*)?>([\s\S]*?)<\/\1>/gi,
      "*$2*"
    )
    .replace(
      /<code(?:[^>"']|"[^"]*"|'[^']*')*>([\s\S]*?)<\/code>/gi,
      (_f, inner: string) => {
        const text = decodeHtmlEntities(stripTags(inner)).trim();
        return text ? `\`${text}\`` : "";
      }
    );

  // 10. Lists and paragraphs and tables
  cleaned = cleaned
    .replace(
      /<li(?:[^>"']|"[^"]*"|'[^']*')*>([\s\S]*?)<\/li>/gi,
      (_f, inner: string) => {
        const item = decodeHtmlEntities(stripTags(inner))
          .replace(/\s+/g, " ")
          .trim();
        return item ? `\n- ${item}` : "";
      }
    )
    .replace(
      /<tr(?:[^>"']|"[^"]*"|'[^']*')*>([\s\S]*?)<\/tr>/gi,
      (_f, row: string) => {
        const cells: string[] = [];
        row.replace(
          /<t[dh](?:[^>"']|"[^"]*"|'[^']*')*>([\s\S]*?)<\/t[dh]>/gi,
          (_c, cell: string) => {
            cells.push(
              decodeHtmlEntities(stripTags(cell)).replace(/\s+/g, " ").trim()
            );
            return "";
          }
        );
        return cells.length > 0 ? `\n| ${cells.join(" | ")} |` : "";
      }
    )
    .replace(
      /<blockquote(?:[^>"']|"[^"]*"|'[^']*')*>([\s\S]*?)<\/blockquote>/gi,
      (_f, inner: string) => {
        const text = decodeHtmlEntities(stripTags(inner))
          .replace(/\s+/g, " ")
          .trim();
        return text ? `\n\n> ${text}\n\n` : "";
      }
    )
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/(p|div|section|article|ul|ol|table|dl)>/gi, "\n\n")
    .replace(/<hr\s*\/?>/gi, "\n\n---\n\n");

  // 11. Strip remaining HTML tags and decode entities
  cleaned = decodeHtmlEntities(stripTags(cleaned));

  // 12. Restore code blocks
  cleaned = cleaned.replace(
    /__WEBCRAWL_CODE_BLOCK_(\d+)__/g,
    (_f, idx: string) => codeBlocks[Number(idx)] || ""
  );

  // 13. Normalize whitespace and prepend meta description if not already in body
  let markdown = cleaned
    .replace(/[ \t]+\n/g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();

  if (metaDescription && !markdown.includes(metaDescription.slice(0, 40))) {
    markdown = `> ${metaDescription}\n\n${markdown}`;
  }

  return {
    title,
    markdown,
    links: Array.from(linksSet),
  };
}

function stripTags(html: string): string {
  return html.replace(/<(?:[^>"']|"[^"]*"|'[^']*')+>/g, " ");
}

/**
 * Fast anchor href extractor for high-speed multi-hop BFS crawling.
 */
export function extractLinksFromHtml(html: string, pageUrl: string): string[] {
  const links: string[] = [];
  const hrefRegex = /<a\s+[^>]*href=["']([^"'#]+)["'][^>]*>/gi;
  let match: RegExpExecArray | null;
  while ((match = hrefRegex.exec(html)) !== null) {
    const rawHref = match[1].trim();
    if (
      !rawHref ||
      rawHref.startsWith("javascript:") ||
      rawHref.startsWith("mailto:") ||
      rawHref.startsWith("tel:")
    ) {
      continue;
    }
    try {
      const resolved = new URL(decodeHtmlEntities(rawHref), pageUrl);
      if (resolved.protocol === "http:" || resolved.protocol === "https:") {
        resolved.hash = "";
        links.push(resolved.toString());
      }
    } catch {
      // ignore invalid URL
    }
  }
  return links;
}

/**
 * Discovers all internal URLs for a website:
 * 1. Checks 24-hour cache first (unless `bypassCache: true`).
 * 2. Probes `robots.txt`, `/sitemap.xml`, `/sitemap_index.xml`, and subpath `sitemap.xml` in parallel.
 * 3. When `sitemap.xml` is missing (or incomplete), performs a full multi-hop concurrent BFS crawl
 *    across the entire website (with automatic `@vercel/sandbox` / browser escalation if the entry page is an SPA),
 *    and caches both the discovered site map and scraped pages for 24 hours.
 */
