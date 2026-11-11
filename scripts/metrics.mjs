#!/usr/bin/env node
// Weekly launch metrics. Uses only public APIs and needs no secrets.
//
//   node scripts/metrics.mjs            # Markdown table to stdout
//   node scripts/metrics.mjs --json     # machine-readable
//
// Set GITHUB_TOKEN to avoid the 60 req/h unauthenticated GitHub limit (CI provides one).
// Hosted signups are not public, so add them by hand from the webcrawl.app admin.
const REPO = process.env.METRICS_REPO || "brainfish-ai/webcrawl-anything";
const PACKAGES = ["webcrawl", "@webcrawl/mcp", "@webcrawl/client", "@webcrawl/curl-impersonate"];
const DAYS = 7;
const since = new Date(Date.now() - DAYS * 864e5);
const sinceDay = since.toISOString().slice(0, 10);
const gh = { Accept: "application/vnd.github+json", "User-Agent": "webcrawl-metrics" };
if (process.env.GITHUB_TOKEN) gh.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;

async function getJson(url, headers = {}) {
  const res = await fetch(url, { headers });
  if (!res.ok) throw new Error(`${res.status} ${url}`);
  return res.json();
}
const search = async (q) => (await getJson(`https://api.github.com/search/issues?per_page=1&q=${encodeURIComponent(q)}`, gh)).total_count;

const repo = await getJson(`https://api.github.com/repos/${REPO}`, gh);
const [prsOpened, prsMerged, externalMerged, issuesOpened, issuesClosed] = await Promise.all([
  search(`repo:${REPO} is:pr created:>=${sinceDay}`),
  search(`repo:${REPO} is:pr is:merged merged:>=${sinceDay}`),
  // PRs from people who are not org members, which is the contributor-flywheel signal.
  getJson(`https://api.github.com/search/issues?per_page=100&q=${encodeURIComponent(`repo:${REPO} is:pr is:merged merged:>=${sinceDay}`)}`, gh).then(
    (r) => new Set(r.items.filter((i) => !["OWNER", "MEMBER", "COLLABORATOR"].includes(i.author_association)).map((i) => i.user.login)).size,
  ),
  search(`repo:${REPO} is:issue created:>=${sinceDay}`),
  search(`repo:${REPO} is:issue closed:>=${sinceDay}`),
]);

// Stars gained in the window: walk stargazers newest-first with timestamps.
let starsGained = 0;
try {
  const last = Math.max(1, Math.ceil(repo.stargazers_count / 100));
  outer: for (let page = last; page >= 1 && page > last - 30; page--) {
    const rows = await getJson(`https://api.github.com/repos/${REPO}/stargazers?per_page=100&page=${page}`, { ...gh, Accept: "application/vnd.github.star+json" });
    for (let i = rows.length - 1; i >= 0; i--) {
      if (new Date(rows[i].starred_at) < since) break outer;
      starsGained++;
    }
  }
} catch {
  starsGained = null; // rate limited; the total is still reported
}

const npm = await Promise.all(
  PACKAGES.map(async (name) => {
    try {
      const r = await getJson(`https://api.npmjs.org/downloads/point/last-week/${name}`);
      return { name, weekly: r.downloads };
    } catch {
      return { name, weekly: null };
    }
  }),
);

const out = {
  date: new Date().toISOString().slice(0, 10),
  window: `${sinceDay} → today`,
  github: {
    stars: repo.stargazers_count,
    starsGained,
    forks: repo.forks_count,
    watchers: repo.subscribers_count,
    openIssues: repo.open_issues_count,
    prsOpened,
    prsMerged,
    externalContributorsMerged: externalMerged,
    issuesOpened,
    issuesClosed,
  },
  npm,
  signups: "manual (webcrawl.app admin)",
};

if (process.argv.includes("--json")) {
  console.log(JSON.stringify(out, null, 2));
} else {
  const g = out.github;
  const fmt = (n) => (n == null ? "n/a" : n.toLocaleString("en-US"));
  console.log(`## Weekly metrics · ${out.date} (${out.window})\n`);
  console.log("| Metric | Value |\n|---|---|");
  console.log(`| ⭐ Stars | ${fmt(g.stars)} (+${fmt(g.starsGained)}) |`);
  console.log(`| Forks / watchers | ${fmt(g.forks)} / ${fmt(g.watchers)} |`);
  console.log(`| PRs opened / merged | ${g.prsOpened} / ${g.prsMerged} |`);
  console.log(`| External contributors merged | ${g.externalContributorsMerged} |`);
  console.log(`| Issues opened / closed | ${g.issuesOpened} / ${g.issuesClosed} (open: ${g.openIssues}) |`);
  for (const p of npm) console.log(`| npm \`${p.name}\` weekly downloads | ${fmt(p.weekly)} |`);
  console.log(`| Hosted signups | _fill in from admin_ |`);
}
