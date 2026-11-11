/**
 * @webcrawl/curl-impersonate — zero-dependency curl-impersonate fetch.
 *
 * One GET hop through a pinned lexiforest curl-impersonate binary with a
 * Chrome TLS/HTTP2 fingerprint. Redirects are manual so callers keep
 * SSRF-guarding each hop. Pairs with the engine fetch ladder as the tier
 * between impit (Chrome 136) and browser/sandbox escalation.
 */

export {
  impersonateFetch,
  ensureImpersonate,
  isImpersonateAvailable,
  resolveBinary,
  parseHeaderDump,
  ImpersonateUnavailableError,
  ImpersonateTimeoutError,
  ResourceTooLargeError,
} from "./fetch.js";
export type {
  ImpersonateFetchOptions,
  ImpersonateFetchResult,
} from "./fetch.js";

export {
  DEFAULT_IMPERSONATE_PROFILE,
  profileHeaders,
  profileUserAgent,
  type ImpersonateProfile,
} from "./profiles.js";

export {
  ensureBinary,
  assetForPlatform,
  binaryCachePath,
  isBinaryCached,
  isBinaryHealthy,
  IMPERSONATE_VERSION,
  ASSET_SHA256,
} from "./binary.js";
