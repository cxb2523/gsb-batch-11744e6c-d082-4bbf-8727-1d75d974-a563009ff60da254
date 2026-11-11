/**
 * Path scoping for map/crawl: restrict discovered URLs to a subpath and/or
 * include/exclude path patterns. Patterns match the URL path (+ query):
 *   "/docs"        prefix at a segment boundary ("/docs", "/docs/a", not "/docs-old")
 *   "/blog/*"      `*` matches any characters
 *   "/api/*\/v1$"  trailing `$` anchors the end
 */

export interface PathScopeOptions {
  includePaths?: string[];
  excludePaths?: string[];
  /** Default true: when the start URL has a path and no includePaths are given, stay under it. */
  restrictToSubpath?: boolean;
}

export interface PathScope {
  allows(url: string): boolean;
  /** Stable string for cache keys. */
  signature: string;
  includes: string[];
  excludes: string[];
}

function toRegExp(pattern: string): RegExp {
  const p = pattern.trim();
  const anchored = p.endsWith("$");
  const raw = anchored ? p.slice(0, -1) : p;
  const hasWildcard = raw.includes("*");
  const body = raw
    .replace(/[.+?^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, ".*");
  if (anchored) return new RegExp(`^${body}$`);
  if (hasWildcard) return new RegExp(`^${body}`);
  // Plain prefix: match at a segment boundary.
  const trimmed = body.replace(/\/+$/, "");
  return new RegExp(`^${trimmed}(?:/|$|\\?)`);
}

function normalizePattern(p: string): string | null {
  let s = String(p ?? "").trim();
  if (!s) return null;
  // Accept full URLs by taking their path.
  if (/^https?:\/\//i.test(s)) {
    try {
      s = new URL(s).pathname;
    } catch {
      return null;
    }
  }
  if (!s.startsWith("/") && !s.startsWith("*")) s = `/${s}`;
  return s;
}

export function buildPathScope(startUrl: string, options: PathScopeOptions = {}): PathScope {
  const clean = (list?: string[]) =>
    (list ?? []).map(normalizePattern).filter((x): x is string => !!x).slice(0, 100);
  let includes = clean(options.includePaths);
  const excludes = clean(options.excludePaths);

  if (includes.length === 0 && options.restrictToSubpath !== false) {
    try {
      const path = new URL(startUrl).pathname.replace(/\/+$/, "");
      if (path && path !== "") includes = [path];
    } catch {
      // ignore invalid start URL
    }
  }

  const inc = includes.map(toRegExp);
  const exc = excludes.map(toRegExp);
  let startKey = "";
  try {
    const u = new URL(startUrl);
    startKey = (u.pathname.replace(/\/+$/, "") || "/") + u.search;
  } catch {
    // ignore
  }

  return {
    includes,
    excludes,
    signature: `inc=${includes.join(",")}|exc=${excludes.join(",")}`,
    allows(url: string) {
      let key: string;
      try {
        const u = new URL(url);
        key = (u.pathname || "/") + u.search;
      } catch {
        return false;
      }
      // The start URL itself is always allowed.
      if ((key.replace(/\/+$/, "") || "/") === startKey) return true;
      if (exc.some((r) => r.test(key))) return false;
      if (inc.length && !inc.some((r) => r.test(key))) return false;
      return true;
    },
  };
}
