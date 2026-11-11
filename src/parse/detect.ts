/**
 * Works out what kind of file a response or upload is, from magic bytes first,
 * then the declared content type, then the file extension.
 */

export type FileKind =
  | "pdf"
  | "docx"
  | "xlsx"
  | "pptx"
  | "image"
  | "audio"
  | "video"
  | "html"
  | "text";

/** Kinds that go through the file parser instead of the HTML pipeline. */
export const BINARY_KINDS: ReadonlySet<FileKind> = new Set(["pdf", "docx", "xlsx", "pptx", "image", "audio", "video"]);

const MIME_KINDS: Array<[RegExp, FileKind]> = [
  [/^application\/pdf$/, "pdf"],
  [/^application\/vnd\.openxmlformats-officedocument\.wordprocessingml/, "docx"],
  [/^application\/vnd\.openxmlformats-officedocument\.spreadsheetml/, "xlsx"],
  [/^application\/vnd\.openxmlformats-officedocument\.presentationml/, "pptx"],
  [/^image\/svg\+xml$/, "text"],
  [/^image\//, "image"],
  [/^audio\//, "audio"],
  [/^video\//, "video"],
  [/^(text\/html|application\/xhtml\+xml)$/, "html"],
  [/^(text\/|application\/(json|xml|csv|x-ndjson|ld\+json|rss\+xml|atom\+xml|javascript))/, "text"],
];

const EXT_KINDS: Record<string, FileKind> = {
  pdf: "pdf",
  docx: "docx",
  xlsx: "xlsx",
  pptx: "pptx",
  png: "image",
  jpg: "image",
  jpeg: "image",
  webp: "image",
  gif: "image",
  heic: "image",
  mp3: "audio",
  wav: "audio",
  m4a: "audio",
  ogg: "audio",
  oga: "audio",
  flac: "audio",
  opus: "audio",
  aac: "audio",
  mp4: "video",
  m4v: "video",
  mov: "video",
  webm: "video",
  mkv: "video",
  html: "html",
  htm: "html",
  txt: "text",
  md: "text",
  csv: "text",
  json: "text",
  xml: "text",
};

/** Content type to send to providers when the declared one is missing or generic. */
export const KIND_DEFAULT_MIME: Partial<Record<FileKind, string>> = {
  pdf: "application/pdf",
  docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  pptx: "application/vnd.openxmlformats-officedocument.presentationml.presentation",
};

function ascii(bytes: Uint8Array, start: number, length: number): string {
  let s = "";
  for (let i = start; i < Math.min(bytes.length, start + length); i++) s += String.fromCharCode(bytes[i]);
  return s;
}

/** Finds which OOXML package a ZIP is by the part names in its local file headers. */
function sniffOoxml(bytes: Uint8Array): FileKind | null {
  const head = ascii(bytes, 0, Math.min(bytes.length, 64 * 1024));
  if (head.includes("word/")) return "docx";
  if (head.includes("xl/")) return "xlsx";
  if (head.includes("ppt/")) return "pptx";
  return null;
}

/** Returns the kind and a concrete mime from the first bytes, or null when unknown. */
export function sniffMagic(bytes: Uint8Array): { kind: FileKind; mime: string } | null {
  if (bytes.length < 4) return null;
  const b = bytes;
  if (ascii(b, 0, 5) === "%PDF-") return { kind: "pdf", mime: "application/pdf" };
  if (b[0] === 0x50 && b[1] === 0x4b && b[2] === 0x03 && b[3] === 0x04) {
    const kind = sniffOoxml(b);
    return kind ? { kind, mime: KIND_DEFAULT_MIME[kind]! } : null;
  }
  if (b[0] === 0x89 && ascii(b, 1, 3) === "PNG") return { kind: "image", mime: "image/png" };
  if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return { kind: "image", mime: "image/jpeg" };
  if (ascii(b, 0, 4) === "GIF8") return { kind: "image", mime: "image/gif" };
  if (ascii(b, 0, 4) === "RIFF" && ascii(b, 8, 4) === "WEBP") return { kind: "image", mime: "image/webp" };
  if (ascii(b, 0, 4) === "RIFF" && ascii(b, 8, 4) === "WAVE") return { kind: "audio", mime: "audio/wav" };
  if (ascii(b, 0, 3) === "ID3" || (b[0] === 0xff && (b[1] & 0xe0) === 0xe0 && (b[1] & 0x06) !== 0)) {
    return { kind: "audio", mime: "audio/mpeg" };
  }
  if (ascii(b, 0, 4) === "fLaC") return { kind: "audio", mime: "audio/flac" };
  if (ascii(b, 0, 4) === "OggS") return { kind: "audio", mime: "audio/ogg" };
  if (b[0] === 0x1a && b[1] === 0x45 && b[2] === 0xdf && b[3] === 0xa3) return { kind: "video", mime: "video/webm" };
  if (ascii(b, 4, 4) === "ftyp") {
    const brand = ascii(b, 8, 4);
    if (/^(heic|heix|mif1|avif)/.test(brand)) return { kind: "image", mime: brand === "avif" ? "image/avif" : "image/heic" };
    if (/^(M4A |M4B )/.test(brand)) return { kind: "audio", mime: "audio/mp4" };
    if (/^qt/.test(brand)) return { kind: "video", mime: "video/quicktime" };
    return { kind: "video", mime: "video/mp4" };
  }
  return null;
}

function extensionOf(name: string | undefined): string {
  if (!name) return "";
  const clean = name.split(/[?#]/)[0];
  const dot = clean.lastIndexOf(".");
  return dot >= 0 ? clean.slice(dot + 1).toLowerCase() : "";
}

export interface DetectInput {
  bytes?: Uint8Array;
  contentType?: string;
  fileName?: string;
}

export interface DetectedFile {
  kind: FileKind;
  /** Best concrete mime for the bytes (used when calling providers). */
  mime: string;
}

/**
 * Magic bytes win over the declared type (servers often send PDFs as
 * octet-stream or text/html); then the declared type; then the extension.
 */
export function detectFileKind({ bytes, contentType, fileName }: DetectInput): DetectedFile {
  const declared = (contentType || "").split(";")[0].trim().toLowerCase();
  const magic = bytes ? sniffMagic(bytes) : null;
  if (magic) return magic;

  const generic = !declared || /^(application\/octet-stream|binary\/octet-stream|application\/zip|application\/x-zip-compressed)$/.test(declared);
  if (!generic) {
    for (const [re, kind] of MIME_KINDS) if (re.test(declared)) return { kind, mime: declared };
  }
  const ext = extensionOf(fileName);
  const byExt = EXT_KINDS[ext];
  if (byExt) {
    const media = byExt === "image" || byExt === "audio" || byExt === "video";
    const sub = ({ mp3: "mpeg", jpg: "jpeg", mov: "quicktime", m4a: "mp4", m4v: "mp4", oga: "ogg" } as Record<string, string>)[ext] || ext;
    return { kind: byExt, mime: KIND_DEFAULT_MIME[byExt] || (media ? `${byExt}/${sub}` : declared || "text/plain") };
  }

  if (bytes) {
    const head = ascii(bytes, 0, 512).toLowerCase();
    if (/<!doctype html|<html[\s>]|<head[\s>]|<body[\s>]/.test(head)) return { kind: "html", mime: "text/html" };
  }
  return { kind: "text", mime: declared || "text/plain" };
}
