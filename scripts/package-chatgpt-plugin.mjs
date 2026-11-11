#!/usr/bin/env node
// Validate plugins/chatgpt and write dist/webcrawl-chatgpt.zip for the
// OpenAI plugin directory (ChatGPT + Codex). No dependencies: uses the system `zip`.
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const dir = join(root, "plugins/chatgpt");
const out = join(root, "dist/webcrawl-chatgpt.zip");
const errors = [];
const fail = (msg) => errors.push(msg);

const readJson = (name) => {
  try {
    return JSON.parse(readFileSync(join(dir, name), "utf8"));
  } catch (e) {
    fail(`${name}: ${e.message}`);
    return {};
  }
};

const plugin = readJson("plugin.json");
const mcp = readJson("mcp.json");
const oa = plugin.extensions?.["com.openai"] ?? {};
const ui = oa.interface ?? {};

// Manifest basics.
if (plugin.$schema !== "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json") fail("plugin.json: wrong $schema");
if (!/^[a-z0-9]+(-[a-z0-9]+)*$/.test(plugin.name ?? "")) fail("plugin.json: name must be kebab-case");
if (!/^\d+\.\d+\.\d+$/.test(plugin.version ?? "")) fail("plugin.json: version must be semver");
for (const k of ["displayName", "shortDescription", "longDescription", "developerName", "category", "websiteURL", "supportURL", "privacyPolicyURL", "termsOfServiceURL"]) {
  if (!ui[k]) fail(`plugin.json: interface.${k} is required`);
}
for (const k of ["websiteURL", "supportURL", "privacyPolicyURL", "termsOfServiceURL"]) {
  if (ui[k] && !String(ui[k]).startsWith("https://")) fail(`plugin.json: interface.${k} must be https`);
}
if (!Array.isArray(ui.defaultPrompt) || ui.defaultPrompt.length < 1) fail("plugin.json: add at least one defaultPrompt");

// Portal limits: name and subtitle are at most 30 characters.
for (const k of ["displayName", "shortDescription"]) {
  const len = [...String(ui[k] ?? "")].length;
  if (len > 30) fail(`plugin.json: interface.${k} is ${len} characters; the portal allows at most 30`);
}
// Category must be a title from the portal's dropdown. Only these are confirmed
// accepted (the portal rejected "Research"); add others once seen in the dashboard.
const CATEGORIES = ["Developer Tools", "Productivity"];
if (ui.category && !CATEGORIES.includes(ui.category)) fail(`plugin.json: interface.category "${ui.category}" is not a known portal category (${CATEGORIES.join(", ")})`);

// Directory copy rules: no "MCP"/"Plugin" suffix, no pricing or promotions.
if (/\b(mcp|plugin)\b/i.test(ui.displayName ?? "")) fail("plugin.json: displayName must not include MCP/Plugin");
const copy = [ui.shortDescription, ui.longDescription, plugin.description, ...(ui.defaultPrompt ?? [])].join(" ");
const banned = copy.match(/\b(free|pricing|price plan|subscription|trial|discount|promo|cheapest|best|anti-bot|bypass)\b/gi);
if (banned) fail(`listing copy uses disallowed wording: ${[...new Set(banned.map((w) => w.toLowerCase()))].join(", ")}`);

// Review cases.
const tc = oa.review?.test_cases ?? {};
// Initial MCP review requires exactly five positive and three negative cases.
if ((tc.positive ?? []).length !== 5) fail(`review.test_cases.positive: needs exactly 5 cases (has ${(tc.positive ?? []).length})`);
if ((tc.negative ?? []).length !== 3) fail(`review.test_cases.negative: needs exactly 3 cases (has ${(tc.negative ?? []).length})`);
if (oa.review?.demo_recording_url && !String(oa.review.demo_recording_url).startsWith("https://")) fail("review.demo_recording_url must be https");
if (!oa.review?.demo_recording_url) console.warn("note: review.demo_recording_url is not set; enter the video URL in the portal or add it here");
for (const c of tc.positive ?? []) if (!c.prompt || !c.tools_triggered || !c.expected_behavior) fail(`positive case "${c.description}" needs prompt, tools_triggered, expected_behavior`);

// Exactly one remote MCP server.
if (mcp.$schema !== "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json") fail("mcp.json: wrong $schema");
const servers = Object.entries(mcp.mcpServers ?? {});
if (servers.length !== 1) fail("mcp.json: declare exactly one MCP server");
for (const [name, s] of servers) {
  if (s.type !== "streamable-http") fail(`mcp.json: ${name} must be streamable-http`);
  if (!String(s.url ?? "").startsWith("https://")) fail(`mcp.json: ${name} url must be https`);
  const extra = Object.keys(s).filter((k) => !["type", "url", "headers"].includes(k));
  if (extra.length) fail(`mcp.json: ${name} has keys the schema rejects: ${extra.join(", ")}`);
}

// Referenced files exist, icons are PNGs.
const refs = [ui.logo, ui.logoDark, ui.composerIcon, ui.composerIconDark, oa.onboardingSkill, ...(ui.screenshots ?? [])].filter(Boolean);
for (const ref of refs) {
  const p = join(dir, ref);
  if (!existsSync(p)) {
    fail(`missing file referenced by plugin.json: ${ref}`);
    continue;
  }
  if (p.endsWith(".png") && readFileSync(p).subarray(0, 8).toString("hex") !== "89504e470d0a1a0a") fail(`${ref} is not a PNG`);
}

// Skills: valid frontmatter.
const skillsDir = join(dir, "skills");
for (const s of existsSync(skillsDir) ? readdirSync(skillsDir) : []) {
  const md = join(skillsDir, s, "SKILL.md");
  if (!existsSync(md)) {
    fail(`skills/${s} has no SKILL.md`);
    continue;
  }
  const fm = readFileSync(md, "utf8").match(/^---\n([\s\S]*?)\n---/);
  if (!fm || !/^name:\s*\S/m.test(fm[1]) || !/^description:\s*\S/m.test(fm[1])) fail(`skills/${s}/SKILL.md needs name and description frontmatter`);
}

// Things the portal rejects or that must never ship.
for (const f of [".app.json", ".mcp.json", "hooks", ".codex-plugin"]) if (existsSync(join(dir, f))) fail(`remove ${f}: not allowed in a directory submission`);
const files = [];
const walk = (d) => {
  for (const e of readdirSync(d)) {
    const p = join(d, e);
    if (statSync(p).isDirectory()) walk(p);
    else files.push(relative(dir, p));
  }
};
walk(dir);
for (const f of files) {
  if (/(^|\/)\.env|\.pem$|\.key$/.test(f)) fail(`secret-like file in package: ${f}`);
  if (!f.endsWith(".png") && /(sk-[A-Za-z0-9]{20,}|wc_[A-Za-z0-9]{20,}|BEGIN [A-Z ]*PRIVATE KEY)/.test(readFileSync(join(dir, f), "utf8"))) fail(`possible credential in ${f}`);
}

if (errors.length) {
  console.error(`plugins/chatgpt is not ready:\n- ${errors.join("\n- ")}`);
  process.exit(1);
}

mkdirSync(dirname(out), { recursive: true });
rmSync(out, { force: true });
// Root of the ZIP is the plugin folder contents (plugin.json at the top level).
execFileSync("zip", ["-q", "-r", "-X", out, ".", "-x", "README.md", "-x", "*.DS_Store"], { cwd: dir, stdio: "inherit" });
const shipped = files.filter((f) => f !== "README.md" && !f.endsWith(".DS_Store"));
console.log(`OK ${plugin.name}@${plugin.version}: ${shipped.length} files -> ${relative(root, out)} (${statSync(out).size} bytes)`);
for (const f of shipped.sort()) console.log(`  ${f}`);
