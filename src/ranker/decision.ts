import { createGateway } from "@ai-sdk/gateway";
import { experimental_decide as decide } from "ai";
import { resolveCountryDisplayName } from "./lexical.js";
import type {
  DecisionModelId,
  SearchFilterContext,
  UserLocationContext,
} from "./types.js";

const DECISION_MODELS: readonly DecisionModelId[] = [
  "baseten/mammoth-1",
  "baseten/elephant-1",
  "convaiinnovations/laya",
  "none",
];

/** What `decisionModel: "auto"` resolves to. Set WEBCRAWL_DECISION_MODEL to change it in prod. */
export function defaultDecisionModel(): DecisionModelId {
  const env = process.env.WEBCRAWL_DECISION_MODEL?.trim() as DecisionModelId | undefined;
  return env && DECISION_MODELS.includes(env) ? env : "baseten/mammoth-1";
}

/**
 * Stage 5: Vercel AI Gateway Decision Model Reranker (`baseten/mammoth-1` & `convaiinnovations/laya`).
 * Scores all top-N candidates in ONE shared-prefix round-trip via `experimental_decide`.
 */
export async function runDecisionModelReranker(
  query: string,
  candidates: Array<{
    title: string;
    url: string;
    description: string;
    highlights: string[];
  }>,
  modelOption: DecisionModelId,
  timeoutMs: number,
  userLocation?: UserLocationContext,
  filterContext?: SearchFilterContext
): Promise<{
  scores: Map<
    number,
    { normalizedScore: number; rawScore: number; confidence: number }
  >;
  modelUsed: string | null;
} | null> {
  // Operator switch: WEBCRAWL_DECISION_MODEL picks what "auto" means (or "none" for lexical-only),
  // so a model price change can be absorbed without a deploy of new code.
  if (modelOption === "auto") modelOption = defaultDecisionModel();
  if (modelOption === "none" || candidates.length === 0) {
    return null;
  }

  const apiKey =
    process.env.AI_GATEWAY_API_KEY || process.env.VERCEL_OIDC_TOKEN;
  if (!apiKey) {
    return null;
  }

  // Primary model selection: `baseten/mammoth-1` (#1 on Jev Decision Index 71.24, ~350ms)
  // or user-specified `convaiinnovations/laya` / `baseten/elephant-1`.
  const primaryModel = modelOption === "auto" ? "baseten/mammoth-1" : modelOption;
  const fallbackModels =
    primaryModel === "baseten/mammoth-1"
      ? ["baseten/elephant-1", "convaiinnovations/laya"]
      : ["baseten/mammoth-1", "baseten/elephant-1"];

  const gw = createGateway({ apiKey });

  const stateCandidates = candidates.map((c, idx) => ({
    id: `doc_${idx}`,
    title: c.title.slice(0, 180),
    url: c.url.slice(0, 200),
    snippet: (c.highlights[0] || c.description || "").slice(0, 360),
  }));

  const contextClauses: string[] = [];
  if (filterContext?.category) {
    contextClauses.push(`category="${filterContext.category}"`);
  }
  if (filterContext?.subcategory) {
    const subStr = Array.isArray(filterContext.subcategory)
      ? filterContext.subcategory.join(", ")
      : filterContext.subcategory;
    contextClauses.push(`subcategory="${subStr}"`);
  }
  if (userLocation?.city || userLocation?.region || userLocation?.country) {
    const locParts = [
      userLocation.city,
      userLocation.region,
      userLocation.countryName ||
        resolveCountryDisplayName(userLocation.country),
    ].filter(Boolean);
    contextClauses.push(`userLocation="${locParts.join(", ")}"`);
  }
  if (filterContext?.customInstruction) {
    contextClauses.push(`agentFilter="${filterContext.customInstruction}"`);
  }
  const contextSuffix =
    contextClauses.length > 0 ? ` (${contextClauses.join("; ")})` : "";

  const questions: Record<
    string,
    {
      type: "score";
      instructions: string;
      criteria: string[];
    }
  > = {};

  for (let i = 0; i < stateCandidates.length; i++) {
    questions[`doc_${i}`] = {
      type: "score",
      instructions: `Evaluate how relevant, authoritative, and aligned candidate doc_${i} is for the search query${contextSuffix}. Penalize entity homonym mismatches or wrong-region pages when userLocation or category is specified.`,
      criteria: [
        "Irrelevant, off-topic, wrong entity, wrong region, or spam",
        "Tangentially related or generic syndication with weak match to the requested category/subcategory/location",
        "Relevant and addresses a substantial part of the query and category/subcategory context",
        "Highly relevant, authoritative, and directly satisfies the query, category, subcategory, and user location",
      ],
    };
  }

  try {
    const decisionPromise = decide({
      model: gw.decisionModel(primaryModel),
      state: JSON.stringify({
        query,
        ...(filterContext?.category
          ? { category: filterContext.category }
          : {}),
        ...(filterContext?.subcategory
          ? { subcategory: filterContext.subcategory }
          : {}),
        ...(userLocation ? { userLocation } : {}),
        candidates: stateCandidates,
      }),
      questions,
      providerOptions: {
        gateway: {
          models: fallbackModels,
        },
      },
      abortSignal: AbortSignal.timeout(timeoutMs),
    });

    const result = await decisionPromise;
    const scores = new Map<
      number,
      { normalizedScore: number; rawScore: number; confidence: number }
    >();

    for (let i = 0; i < stateCandidates.length; i++) {
      const ans = result.answers?.[`doc_${i}`] as
        | {
            type?: string;
            score?: number;
            confidence?: number;
            probabilities?: Record<string, number> | number[];
          }
        | undefined;
      if (!ans) {
        continue;
      }

      let rawScore = typeof ans.score === "number" ? ans.score : 0;
      let maxProb = typeof ans.confidence === "number" ? ans.confidence : 0;

      if (ans.probabilities) {
        const probs = Array.isArray(ans.probabilities)
          ? ans.probabilities
          : [
              Number(ans.probabilities["0"] ?? 0),
              Number(ans.probabilities["1"] ?? 0),
              Number(ans.probabilities["2"] ?? 0),
              Number(ans.probabilities["3"] ?? 0),
            ];
        const expected =
          0 * (probs[0] || 0) +
          1 * (probs[1] || 0) +
          2 * (probs[2] || 0) +
          3 * (probs[3] || 0);
        if (expected > 0 || rawScore === 0) {
          rawScore = expected;
        }
        maxProb = Math.max(maxProb, ...probs.filter((p) => Number.isFinite(p)));
      }

      const normalizedScore = Math.max(0, Math.min(1, rawScore / 3));
      scores.set(i, {
        normalizedScore,
        rawScore: Number(rawScore.toFixed(4)),
        confidence: Number((maxProb || 0.85).toFixed(4)),
      });
    }

    const modelUsed =
      (result as { response?: { modelId?: string } }).response?.modelId ||
      primaryModel;

    return { scores, modelUsed };
  } catch {
    return null;
  }
}

/**
 * Full 5-Stage Document & Passage Ranking Pipeline:
 * 1. Canonical URL Deduplication
 * 2. Weighted Reciprocal Rank Fusion (W-RRF, k=60) + Multi-Engine Consensus
 * 3. Fielded Okapi BM25F+ (title 3.5x, headings 2.2x, url 2.0x, description 1.5x, body 1.0x)
 * 4. ColBERT-inspired Subword + Token MaxSim Passage Scoring & Highlight Extraction
 * 5. Vercel AI Gateway Decision Model Reranking (`baseten/mammoth-1` / `convaiinnovations/laya`)
 */
