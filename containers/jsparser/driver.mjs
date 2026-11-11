// ReverseAI jsparser driver (contract "JavaScript syntax through a pinned parser", decisions m5b-contract,
// m5b-seams-w, m5b-seams-h, m5b-seams-h2, m5b-callee-suffix): parses JavaScript text as data with @babel/parser only.
//
// One fixed request on stdin from worker.py: {"files": [{"path", "dialect"}], "kind", "start", "limit", "callees"}.
// One answer on stdout: {"files": [{"status", "errors", "count", "items": [[form, start, end], ...]}]}, one row per
// file in request order; items are that file's part of the page [start, start + limit) over all files' items in
// request order, each file's items sorted by start, end and form. Offsets are UTF-16 units of the decoded text after
// one leading BOM. Nothing here evaluates, imports, requires or transpiles the text; Node runs with code generation
// from strings disallowed and the permission model limited to reading this folder and the worker's files.
import { parse } from "@babel/parser";
import { readFileSync } from "node:fs";

const MAX_FILE = 4 * 1024 * 1024;
const MAX_CALLEE = 255;
const PLUGINS = { js: [], jsx: ["jsx"], ts: ["typescript"], tsx: ["typescript", "jsx"] };
const FORMS = ["import", "export_from", "require", "dynamic_import", "call"];
// Plain ASCII identifiers joined by dots, at most four parts; anything else (escapes, other identifiers, spaces or
// comments inside the chain) is omitted, so the host can check every byte (decision m5b-seams-h).
const CHAIN = /^[$A-Za-z_][$A-Za-z0-9_]*(?:\.[$A-Za-z_][$A-Za-z0-9_]*){0,3}$/;
const SKIP = new Set(["loc", "start", "end", "extra", "range", "leadingComments", "trailingComments",
                      "innerComments", "errors", "comments", "tokens"]);

const request = JSON.parse(readFileSync(0, "utf8"));
const entries = new Set(request.callees);

function literal(node) {
  // A quoted string, or a template without substitutions whose cooked value exists (a template holding a legacy
  // octal or \8 escape has none, so the host could not decode it).
  return node != null && (node.type === "StringLiteral"
    || (node.type === "TemplateLiteral" && node.expressions.length === 0 && node.quasis.length === 1
        && node.quasis[0].value.cooked != null));
}

function callee(text, node) {
  // The callee's own source text; a call item only when its trailing one or two parts equal an entry.
  if (node.type !== "Identifier" && node.type !== "MemberExpression") return false;
  const source = text.slice(node.start, node.end);
  if (source.length > MAX_CALLEE || !CHAIN.test(source)) return false;
  const parts = source.split(".");
  return entries.has(parts[parts.length - 1]) || (parts.length > 1 && entries.has(parts.slice(-2).join(".")));
}

function items(text, ast, kind) {
  const found = [];
  const stack = [ast.program];
  while (stack.length) {
    const node = stack.pop();
    if (Array.isArray(node)) {
      for (let i = node.length - 1; i >= 0; i--) if (node[i] && typeof node[i] === "object") stack.push(node[i]);
      continue;
    }
    if (kind === "modules") {
      if (node.type === "ImportDeclaration" && literal(node.source)) found.push(["import", node.source]);
      else if ((node.type === "ExportNamedDeclaration" || node.type === "ExportAllDeclaration") && literal(node.source))
        found.push(["export_from", node.source]);
      else if (node.type === "ImportExpression" && literal(node.source)) found.push(["dynamic_import", node.source]);
      else if (node.type === "CallExpression" && node.callee.type === "Import" && literal(node.arguments[0]))
        found.push(["dynamic_import", node.arguments[0]]);
      else if (node.type === "CallExpression" && node.callee.type === "Identifier" && node.callee.name === "require"
               && literal(node.arguments[0])) found.push(["require", node.arguments[0]]);
      else if (node.type === "TSExternalModuleReference" && literal(node.expression))
        found.push(["require", node.expression]);
    } else if ((node.type === "CallExpression" || node.type === "NewExpression") && callee(text, node.callee)) {
      found.push(["call", node.callee]);
    }
    for (const key of Object.keys(node)) {
      if (SKIP.has(key)) continue;
      const value = node[key];
      if (value && typeof value === "object") stack.push(value);
    }
  }
  const rows = found.map(([form, node]) => [form, node.start, node.end]);
  rows.sort((a, b) => a[1] - b[1] || a[2] - b[2] || FORMS.indexOf(a[0]) - FORMS.indexOf(b[0]));
  return rows.filter((row, i) => i === 0 || row.some((value, j) => value !== rows[i - 1][j]));
}

const decoder = new TextDecoder("utf-8", { fatal: true });  // ignoreBOM false: one leading BOM is skipped
const answer = [];
let before = 0;  // items of the earlier files, in page order
for (const file of request.files) {
  const bytes = readFileSync(file.path);
  let row = { status: "ok", errors: 0, count: 0, items: [] };
  if (bytes.length > MAX_FILE) row.status = "too_large";
  else {
    let text = null;
    try { text = decoder.decode(bytes); } catch { row.status = "decode_error"; }
    if (text !== null) {
      let ast = null;
      try {
        ast = parse(text, { sourceType: "unambiguous", errorRecovery: true, plugins: PLUGINS[file.dialect] });
      } catch {
        row = { status: "syntax_error", errors: 1, count: 0, items: [] };  // no tree to recover from
      }
      if (ast !== null) {
        row.errors = ast.errors ? ast.errors.length : 0;
        row.status = row.errors ? "syntax_error" : "ok";
        if (request.kind !== "parse") {
          const found = items(text, ast, request.kind);
          row.count = found.length;
          const first = Math.max(0, request.start - before);
          const last = Math.min(found.length, request.start + request.limit - before);
          row.items = first < last ? found.slice(first, last) : [];
          before += found.length;
        }
      }
    }
  }
  answer.push(row);
}
process.stdout.write(JSON.stringify({ files: answer }));
