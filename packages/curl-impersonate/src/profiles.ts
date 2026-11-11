/**
 * Browser impersonation profiles for the lexiforest curl-impersonate binary.
 *
 * The binary ships presets as `--impersonate <target>`; the target names here
 * map 1:1 to the wrapper scripts in the release tarball (curl_chrome150 etc.).
 * Presets bundle TLS ciphers/curves/extensions, HTTP/2 settings + pseudo-header
 * order, and a default navigation header set — we override the UA/sec-ch-ua
 * headers ourselves so they stay coherent with `sec-ch-ua-platform`.
 */

export type ImpersonateProfile =
  | "chrome142"
  | "chrome150"
  | "chrome151_macos"
  | "chrome152";

export const DEFAULT_IMPERSONATE_PROFILE: ImpersonateProfile = "chrome150";

interface ProfileDef {
  /** Major version used in sec-ch-ua and the UA string. */
  chromeMajor: string;
  /** Platform token in the UA + `sec-ch-ua-platform`. */
  platform: "macOS" | "Windows";
  /** UA template override (defaults to the macOS Chrome template). */
}

const PROFILE_DEFS: Record<ImpersonateProfile, ProfileDef> = {
  chrome142: { chromeMajor: "142", platform: "macOS" },
  chrome150: { chromeMajor: "150", platform: "macOS" },
  chrome151_macos: { chromeMajor: "151", platform: "macOS" },
  chrome152: { chromeMajor: "152", platform: "macOS" },
};

const MAC_UA = (v: string) =>
  `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${v}.0.0.0 Safari/537.36`;

const WIN_UA = (v: string) =>
  `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${v}.0.0.0 Safari/537.36`;

/**
 * Fingerprint-coherent navigation headers for a profile: the UA, the
 * client hints, and the Sec-Fetch navigation set a real Chrome tab sends.
 * The binary replaces the TLS/HTTP2 layer; these headers keep the
 * application layer consistent with it.
 */
export function profileHeaders(
  profile: ImpersonateProfile = DEFAULT_IMPERSONATE_PROFILE,
  extra?: Record<string, string>
): Record<string, string> {
  const def = PROFILE_DEFS[profile];
  const v = def.chromeMajor;
  return {
    "User-Agent": def.platform === "macOS" ? MAC_UA(v) : WIN_UA(v),
    "sec-ch-ua": `"Chromium";v="${v}", "Google Chrome";v="${v}", "Not.A/Brand";v="99"`,
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": `"${def.platform}"`,
    "Upgrade-Insecure-Requests": "1",
    Accept:
      "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-User": "?1",
    "Sec-Fetch-Dest": "document",
    "Accept-Language": "en-US,en;q=0.9",
    Priority: "u=0, i",
    ...(extra ?? {}),
  };
}

export function profileUserAgent(
  profile: ImpersonateProfile = DEFAULT_IMPERSONATE_PROFILE
): string {
  return profileHeaders(profile)["User-Agent"];
}
