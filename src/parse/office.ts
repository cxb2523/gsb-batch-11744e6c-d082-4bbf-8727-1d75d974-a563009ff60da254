/**
 * DOCX / XLSX / PPTX -> Markdown, locally with officeparser (no network, no model).
 * Sheets and slides get their own headings so a reader can tell where content came from.
 */
import type { FileKind } from "./detect.js";
import type { ParsedFile } from "./types.js";

type OfficeKind = Extract<FileKind, "docx" | "xlsx" | "pptx">;

interface AstNode {
  type: string;
  metadata?: { sheetName?: string; slideNumber?: number };
}

/** Removes YAML front matter and `{#anchor}` heading ids officeparser adds. */
export function cleanOfficeMarkdown(md: string): string {
  return md
    // Only strip a leading block that is really YAML (every line `key: value`); PPTX output
    // also starts with `---`, and there the block is slide 1.
    .replace(/^---\n((?:[\w:-]+:.*\n)+)---\n?/, "")
    .replace(/^(#{1,6} .*?)[ \t]*\{#[^}]+\}[ \t]*$/gm, "$1")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

/**
 * officeparser separates slides / sheets with `---` lines. Split on those so each
 * section can be labelled with the slide number or sheet name from the AST.
 */
export function splitSections(md: string): string[] {
  return md
    .split(/^---\s*$/m)
    .map((s) => s.trim())
    .filter(Boolean);
}

export function labelSections(
  kind: OfficeKind,
  sections: string[],
  nodes: AstNode[]
): { markdown: string; units: number; empty: string[] } {
  if (kind === "docx") return { markdown: sections.join("\n\n---\n\n"), units: 1, empty: [] };

  const unitType = kind === "xlsx" ? "sheet" : "slide";
  const units = nodes.filter((n) => n.type === unitType);
  const empty: string[] = [];
  const out: string[] = [];
  // Empty sheets/slides produce no section, so match non-empty sections to units in order.
  let si = 0;
  units.forEach((u, i) => {
    const label =
      kind === "xlsx"
        ? `## Sheet: ${u.metadata?.sheetName || `Sheet ${i + 1}`}`
        : `<!-- slide ${u.metadata?.slideNumber ?? i + 1} -->`;
    const isEmpty = kind === "xlsx" ? (u as { children?: unknown[] }).children?.length === 0 : false;
    if (isEmpty) {
      empty.push(u.metadata?.sheetName || `Sheet ${i + 1}`);
      return;
    }
    const body = sections[si++];
    if (body !== undefined) out.push(`${label}\n\n${body}`);
  });
  // Anything left over (AST and Markdown disagree) is kept rather than dropped.
  while (si < sections.length) out.push(sections[si++]);
  return { markdown: out.join("\n\n"), units: units.length || sections.length, empty };
}

export async function parseOffice(bytes: Uint8Array, kind: OfficeKind, mime: string): Promise<ParsedFile> {
  const started = performance.now();
  const { OfficeConverter, OfficeParser } = await import("officeparser");
  const buf = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const parseConfig = { fileType: kind, ignoreNotes: false };

  const [converted, ast] = await Promise.all([
    OfficeConverter.convert(buf, "md" as never, { parseConfig } as never),
    OfficeParser.parseOffice(buf, parseConfig as never),
  ]);

  const cleaned = cleanOfficeMarkdown(String(converted.value ?? ""));
  const nodes = (ast.content ?? []) as unknown as AstNode[];
  const { markdown, units, empty } = labelSections(kind, splitSections(cleaned), nodes);

  const warnings = (converted.messages ?? [])
    .filter((m) => (m as { type?: string }).type === "warning")
    .map((m) => String((m as { message?: string }).message ?? m))
    .slice(0, 10);
  if (empty.length) warnings.push(`Empty sheets: ${empty.join(", ")}`);

  const title =
    (ast.metadata as { title?: string } | undefined)?.title?.trim() ||
    markdown.match(/^#\s+(.+)$/m)?.[1]?.trim() ||
    "";

  return {
    title,
    markdown,
    meta: {
      kind,
      mime,
      method: "native",
      bytes: bytes.byteLength,
      // "pages" means sheets for XLSX and slides for PPTX; DOCX has no reliable page count.
      ...(kind === "docx" ? {} : { pages: units }),
      warnings,
      processingMs: Math.round(performance.now() - started),
    },
  };
}
