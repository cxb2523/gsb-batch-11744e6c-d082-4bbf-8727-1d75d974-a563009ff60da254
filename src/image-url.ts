/**
 * Client-safe helper (no Node imports): turn an external image URL into our
 * same-origin `/img` proxy URL. See `image-proxy.ts` for the server side.
 */
export function proxiedImage(src: string | undefined): string | undefined {
  if (!src) {
    return undefined;
  }
  if (src.startsWith("/") && !src.startsWith("//")) {
    return src; // already local
  }
  return `/img?url=${encodeURIComponent(src)}`;
}
