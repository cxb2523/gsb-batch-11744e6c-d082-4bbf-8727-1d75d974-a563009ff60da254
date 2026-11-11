export type SearchEngineSource =
  | "bing-shopping"
  | "google-shopping"
  | "brave-native"
  | "ddg-lite"
  | "bing-rss"
  | "google-news-rss"
  | "wikipedia"
  | "hn-algolia"
  | "arxiv"
  | "nvd"
  | "osv"
  | "serper"
  | "brave-api"
  | "jina";

export type DecisionModelId =
  | "baseten/mammoth-1"
  | "baseten/elephant-1"
  | "convaiinnovations/laya"
  | "auto"
  | "none";

export interface RawCandidateDocument {
  title: string;
  url: string;
  description: string;
  markdown?: string;
  links?: string[];
  publishedDate?: string;
  engine?: SearchEngineSource;
  engineRank?: number;
  sources?: SearchEngineSource[];
  engineRanks?: Partial<Record<SearchEngineSource, number>>;
}

export interface UserLocationContext {
  country?: string;
  countryName?: string;
  region?: string;
  city?: string;
  timezone?: string;
  latitude?: number;
  longitude?: number;
}

export interface SearchFilterContext {
  category?: string;
  subcategory?: string | string[];
  preferLocalDomains?: boolean;
  boostTerms?: string[];
  mustIncludeTerms?: string[];
  excludeTerms?: string[];
  customInstruction?: string;
}

export interface DocumentScoreBreakdown {
  rrfScore: number;
  bm25fScore: number;
  passageMaxSimScore: number;
  proximityScore: number;
  freshnessAuthorityScore: number;
  geoAffinityScore?: number;
  lexicalHybridScore: number;
  decisionScore?: number;
  decisionRawScore?: number;
  decisionConfidence?: number;
  decisionModelUsed?: string;
  multiEngineConsensusCount: number;
}

export interface RankedDocument {
  title: string;
  url: string;
  canonicalUrl: string;
  description: string;
  markdown?: string;
  links?: string[];
  publishedDate?: string;
  score: number;
  rank: number;
  sources: SearchEngineSource[];
  highlights: string[];
  scoreBreakdown: DocumentScoreBreakdown;
}

export interface RerankOptions {
  topK?: number;
  rrfK?: number;
  useDecisionModel?: boolean;
  decisionModel?: DecisionModelId;
  decisionTimeoutMs?: number;
  decisionTopN?: number;
  extractHighlights?: boolean;
  maxHighlights?: number;
  /** Maximum results per publisher/domain in topK when diverse candidates exist (default: 1 for topK <= 10, 2 for topK > 10) */
  maxPerDomain?: number;
  /** Maximal Marginal Relevance lambda in [0, 1] balancing relevance vs diversity (default: 0.82) */
  mmrLambda?: number;
  /** Optional user geolocation context for boosting local/regional sources and ccTLDs */
  userLocation?: UserLocationContext;
  /** Optional dynamic category, subcategory, and agent filter context */
  filterContext?: SearchFilterContext;
}

export interface RerankResult {
  results: RankedDocument[];
  rankingMetrics: {
    totalCandidates: number;
    uniqueCandidates: number;
    lexicalLatencyMs: number;
    decisionLatencyMs: number;
    totalRankingLatencyMs: number;
    decisionModelUsed: string | null;
    enginesContributing: SearchEngineSource[];
  };
}
