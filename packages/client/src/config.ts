import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

export const DEFAULT_BASE_URL = "https://webcrawl.app";

export type ExecutionMode = "local" | "cloud" | "auto";

export interface FileConfig {
  apiKey?: string;
  baseUrl?: string;
  mode?: ExecutionMode;
}

export interface ResolvedConfig {
  apiKey?: string;
  baseUrl: string;
  mode: ExecutionMode;
  effectiveMode: "local" | "cloud";
  source: {
    apiKey: "flag" | "env" | "file" | "none";
    baseUrl: "flag" | "env" | "file" | "default";
    mode: "flag" | "env" | "file" | "default";
  };
}

export function configPath(env: NodeJS.ProcessEnv = process.env): string {
  const base = env.XDG_CONFIG_HOME || join(homedir(), ".config");
  return join(base, "webcrawl", "config.json");
}

export function readConfigFile(path = configPath()): FileConfig {
  try {
    const parsed: unknown = JSON.parse(readFileSync(path, "utf8"));
    if (parsed && typeof parsed === "object") {
      const o = parsed as Record<string, unknown>;
      return {
        apiKey: typeof o.apiKey === "string" ? o.apiKey : undefined,
        baseUrl: typeof o.baseUrl === "string" ? o.baseUrl : undefined,
        mode: o.mode === "local" || o.mode === "cloud" || o.mode === "auto" ? o.mode : undefined,
      };
    }
  } catch {
    // missing or unreadable config is fine
  }
  return {};
}

export function writeConfigFile(cfg: FileConfig, path = configPath()): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  writeFileSync(path, `${JSON.stringify(cfg, null, 2)}\n`, { mode: 0o600 });
  chmodSync(path, 0o600);
}

const clean = (v: string | undefined) => (v && v.trim() ? v.trim() : undefined);

/** Precedence: explicit flags > environment > config file > defaults. */
export function resolveConfig(
  flags: { apiKey?: string; baseUrl?: string; mode?: string } = {},
  env: NodeJS.ProcessEnv = process.env,
  file: FileConfig = readConfigFile(configPath(env))
): ResolvedConfig {
  const pick = <S extends string>(
    f: string | undefined,
    e: string | undefined,
    fl: string | undefined,
    none: S
  ): [string | undefined, "flag" | "env" | "file" | S] => {
    if (clean(f)) {return [clean(f), "flag"];}
    if (clean(e)) {return [clean(e), "env"];}
    if (clean(fl)) {return [clean(fl), "file"];}
    return [undefined, none];
  };
  const [apiKey, keySrc] = pick(flags.apiKey, env.WEBCRAWL_API_KEY, file.apiKey, "none");
  const [baseUrl, urlSrc] = pick(flags.baseUrl, env.WEBCRAWL_URL, file.baseUrl, "default");
  const [rawMode, modeSrc] = pick(flags.mode, env.WEBCRAWL_MODE, file.mode, "default");
  const mode: ExecutionMode =
    rawMode === "local" || rawMode === "cloud" || rawMode === "auto" ? rawMode : "auto";
  const effectiveMode: "local" | "cloud" =
    mode === "local" ? "local" : mode === "cloud" ? "cloud" : apiKey ? "cloud" : "local";

  return {
    apiKey,
    baseUrl: (baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, ""),
    mode,
    effectiveMode,
    source: { apiKey: keySrc, baseUrl: urlSrc, mode: modeSrc },
  };
}
