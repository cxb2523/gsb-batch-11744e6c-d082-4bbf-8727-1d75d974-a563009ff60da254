#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   npm run release -- [patch|minor|major|<explicit-version>] [--no-publish] [--no-push]
#
# Examples:
#   npm run release -- patch          # bumps 1.2.2 -> 1.2.3, builds, tests, publishes to npm (if NPM_TOKEN in .env.local), commits, tags v1.2.3, pushes to opensource
#   npm run release -- 1.3.0          # sets version 1.3.0 across all packages, publishes & pushes tag

BUMP="${1:-patch}"
NO_PUBLISH=false
NO_PUSH=false

for arg in "$@"; do
  case "$arg" in
    --no-publish) NO_PUBLISH=true ;;
    --no-push) NO_PUSH=true ;;
  esac
done

NEW_VERSION=$(node -e '
const fs = require("fs");
const bump = process.argv[1];
const rootPkg = JSON.parse(fs.readFileSync("package.json", "utf8"));
const current = rootPkg.version;
let next = bump;
if (["patch", "minor", "major"].includes(bump)) {
  const [maj, min, pat] = current.split(".").map((n) => parseInt(n, 10));
  if (bump === "major") next = `${maj + 1}.0.0`;
  if (bump === "minor") next = `${maj}.${min + 1}.0`;
  if (bump === "patch") next = `${maj}.${min}.${pat + 1}`;
} else if (bump === "none" || bump.startsWith("--")) {
  next = current;
} else if (!/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(bump)) {
  console.error(`Invalid version or bump type: ${bump}`);
  process.exit(1);
}

const files = [
  "package.json",
  "packages/client/package.json",
  "packages/mcp/package.json",
  "packages/cli/package.json",
  "packages/curl-impersonate/package.json",
];

for (const file of files) {
  const pkg = JSON.parse(fs.readFileSync(file, "utf8"));
  pkg.version = next;
  for (const depField of ["dependencies", "devDependencies", "optionalDependencies"]) {
    if (!pkg[depField]) continue;
    if (pkg[depField]["@webcrawl/client"]) pkg[depField]["@webcrawl/client"] = `^${next}`;
    if (pkg[depField]["@webcrawl/mcp"]) pkg[depField]["@webcrawl/mcp"] = `^${next}`;
    if (pkg[depField]["@webcrawl/curl-impersonate"]?.startsWith("^")) {
      pkg[depField]["@webcrawl/curl-impersonate"] = `^${next}`;
    }
  }
  fs.writeFileSync(file, JSON.stringify(pkg, null, 2) + "\n");
}

// Keep the MCP Registry metadata on the same version as the npm package it points at.
const server = JSON.parse(fs.readFileSync("server.json", "utf8"));
server.version = next;
for (const p of server.packages ?? []) {
  if (p.identifier === "@webcrawl/mcp") p.version = next;
}
fs.writeFileSync("server.json", JSON.stringify(server, null, 2) + "\n");
process.stdout.write(next);
' "$BUMP")

echo "→ Prepared release v${NEW_VERSION}"

RELEASE_PATHS=(
  package.json
  package-lock.json
  packages/client/package.json
  packages/mcp/package.json
  packages/cli/package.json
  packages/curl-impersonate/package.json
  server.json
)

# Keep package-lock.json in sync with the bumped workspace versions so npm
# continues to link @webcrawl/* locally. Without this, `npm ci` / packed
# installs look for the new version on the registry (ETARGET) before publish.
if ! git diff --quiet -- package.json packages/*/package.json server.json; then
  echo "→ Refreshing package-lock.json so @webcrawl/* stay workspace-linked"
  npm install --package-lock-only --ignore-scripts --no-audit --no-fund
  node -e '
    const lock = JSON.parse(require("fs").readFileSync("package-lock.json", "utf8"));
    const names = ["@webcrawl/client", "@webcrawl/mcp", "@webcrawl/curl-impersonate", "webcrawl"];
    const missing = names.filter((name) => !lock.packages?.[`node_modules/${name}`]?.link);
    if (missing.length) {
      console.error("package-lock.json must workspace-link:", missing.join(", "));
      process.exit(1);
    }
    console.log("→ Workspace links:", names.join(", "));
  '
fi

npm run build:packages
npm run test:packages

if ! git diff --quiet -- "${RELEASE_PATHS[@]}"; then
  git add "${RELEASE_PATHS[@]}"
  git commit -m "chore(release): v${NEW_VERSION}"
fi

if ! git rev-parse "v${NEW_VERSION}" >/dev/null 2>&1; then
  git tag -a "v${NEW_VERSION}" -m "Release v${NEW_VERSION}"
fi

if [ "$NO_PUBLISH" = false ]; then
  set -a
  [ -f .env ] && source .env
  [ -f .env.local ] && source .env.local
  set +a
  TOKEN="${NPM_TOKEN:-${NPM_PUBLISH_TOKEN:-${NODE_AUTH_TOKEN:-}}}"
  if [ -n "$TOKEN" ]; then
    echo "→ Publishing v${NEW_VERSION} to npm using local token..."
    TMP_NPMRC=$(mktemp)
    trap 'rm -f "$TMP_NPMRC"' EXIT
    printf "//registry.npmjs.org/:_authToken=%s\n" "$TOKEN" > "$TMP_NPMRC"

    npm publish --workspace=packages/client --access public --userconfig "$TMP_NPMRC" --cache /tmp/npm-cache || true
    for i in $(seq 1 24); do
      if [ "$(npm view "@webcrawl/client@${NEW_VERSION}" version --cache /tmp/npm-cache 2>/dev/null || true)" = "$NEW_VERSION" ]; then
        break
      fi
      sleep 3
    done
    npm publish --workspace=packages/mcp --access public --userconfig "$TMP_NPMRC" --cache /tmp/npm-cache || true
    for i in $(seq 1 24); do
      if [ "$(npm view "@webcrawl/mcp@${NEW_VERSION}" version --cache /tmp/npm-cache 2>/dev/null || true)" = "$NEW_VERSION" ]; then
        break
      fi
      sleep 3
    done
    npm publish --workspace=packages/curl-impersonate --access public --userconfig "$TMP_NPMRC" --cache /tmp/npm-cache || true
    for i in $(seq 1 24); do
      if [ "$(npm view "@webcrawl/curl-impersonate@${NEW_VERSION}" version --cache /tmp/npm-cache 2>/dev/null || true)" = "$NEW_VERSION" ]; then
        break
      fi
      sleep 3
    done
    npm publish --workspace=packages/cli --access public --userconfig "$TMP_NPMRC" --cache /tmp/npm-cache || true
  else
    echo "→ No local NPM_TOKEN found; pushing tag v${NEW_VERSION} will trigger GitHub Actions release.yml"
  fi
fi

if [ "$NO_PUSH" = false ]; then
  REMOTE="opensource"
  if ! git remote get-url "$REMOTE" >/dev/null 2>&1; then
    REMOTE="origin"
  fi
  echo "→ Pushing main and tag v${NEW_VERSION} to ${REMOTE}..."
  git push "$REMOTE" HEAD:main
  git push "$REMOTE" "v${NEW_VERSION}"
fi

echo "✓ Release v${NEW_VERSION} complete!"
