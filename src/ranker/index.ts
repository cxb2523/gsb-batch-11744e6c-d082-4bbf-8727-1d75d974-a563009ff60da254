export * from "./types.js";

export * from "./lexical.js";

export * from "./decision.js";

import { runDecisionModelReranker } from "./decision.js";
import {
  computeFreshnessAndAuthorityScore,
  computeGeoAffinityScore,
  computePassageMaxSimAndHighlights,
  computeProximityAndExactScore,
  computeTokenSimilarity,
  extractMarkdownHeadings,
  extractPublisherDomainKey,
  fuseWithWeightedRrf,
  tokenizeAndHash,
} from "./lexical.js";
import type {
  DecisionModelId,
  DocumentScoreBreakdown,
  RankedDocument,
  RawCandidateDocument,
  RerankOptions,
  RerankResult,
} from "./types.js";

export async function rankDocuments(
  query: string,
  rawCandidates: RawCandidateDocument[],
  options: RerankOptions = {}
): Promise<RerankResult> {
  const startTotal = performance.now();
  const topK = Math.min(Math.max(options.topK ?? 10, 1), 50);
  const rrfK = options.rrfK ?? 60;
  const useDecisionModel = options.useDecisionModel !== false;
  const decisionModel: DecisionModelId = options.decisionModel ?? "auto";
  const decisionTimeoutMs = options.decisionTimeoutMs ?? 1200;
  const decisionTopN = Math.min(options.decisionTopN ?? 10, 16);
  const maxHighlights = options.maxHighlights ?? 2;

  if (rawCandidates.length === 0) {
    return {
      results: [],
      rankingMetrics: {
        totalCandidates: 0,
        uniqueCandidates: 0,
        lexicalLatencyMs: 0,
        decisionLatencyMs: 0,
        totalRankingLatencyMs: 0,
        decisionModelUsed: null,
        enginesContributing: [],
      },
    };
  }

  // Stage 1 & 2: Canonical deduplication + Weighted RRF
  const { merged, enginesContributing } = fuseWithWeightedRrf(
    rawCandidates,
    rrfK
  );
  const N = merged.length;

  // Tokenize query once
  const rawQueryLower = query.trim().toLowerCase();
  const queryTok = tokenizeAndHash(query, true);

  // Pre-tokenize all document fields for Fielded BM25F+
  const FIELD_WEIGHTS = {
    title: 3.5,
    headings: 2.2,
    url: 2.0,
    description: 1.5,
    body: 1.0,
  };

  const docFields = merged.map((item) => {
    const titleTok = tokenizeAndHash(item.doc.title || "");
    const headingsTok = tokenizeAndHash(
      extractMarkdownHeadings(item.doc.markdown)
    );
    const urlTok = tokenizeAndHash(
      item.canonicalUrl.replace(/https?:\/\//, " ")
    );
    const descTok = tokenizeAndHash(item.doc.description || "");
    const bodyTok = tokenizeAndHash((item.doc.markdown || "").slice(0, 12000));

    const weightedLen =
      titleTok.hashes.length * FIELD_WEIGHTS.title +
      headingsTok.hashes.length * FIELD_WEIGHTS.headings +
      urlTok.hashes.length * FIELD_WEIGHTS.url +
      descTok.hashes.length * FIELD_WEIGHTS.description +
      bodyTok.hashes.length * FIELD_WEIGHTS.body;

    return {
      titleTok,
      headingsTok,
      urlTok,
      descTok,
      bodyTok,
      weightedLen: Math.max(1, weightedLen),
    };
  });

  const avgWeightedLen =
    docFields.reduce((acc, f) => acc + f.weightedLen, 0) / Math.max(1, N);

  // Compute Document Frequency (DF) per query term across the candidate pool
  const dfMap = new Map<number, number>();
  for (let qi = 0; qi < queryTok.hashes.length; qi++) {
    const qHash = queryTok.hashes[qi];
    let df = 0;
    for (let di = 0; di < N; di++) {
      const f = docFields[di];
      if (
        f.titleTok.freqMap.has(qHash) ||
        f.headingsTok.freqMap.has(qHash) ||
        f.urlTok.freqMap.has(qHash) ||
        f.descTok.freqMap.has(qHash) ||
        f.bodyTok.freqMap.has(qHash)
      ) {
        df++;
      }
    }
    dfMap.set(qHash, df);
  }

  // Stage 3: Fielded BM25F+ (`k1 = 1.5, b = 0.75, delta = 1.0`)
  const k1 = 1.5;
  const b = 0.75;
  const delta = 1.0;
  const bm25RawScores = new Float32Array(N);
  let maxBm25 = 0;
  let maxRrf = 0;

  for (let di = 0; di < N; di++) {
    const f = docFields[di];
    const normFactor =
      1 - b + b * (f.weightedLen / Math.max(1, avgWeightedLen));
    let docBm25 = 0;

    for (let qi = 0; qi < queryTok.hashes.length; qi++) {
      const qHash = queryTok.hashes[qi];
      const pseudoTf =
        ((f.titleTok.freqMap.get(qHash) ?? 0) * FIELD_WEIGHTS.title +
          (f.headingsTok.freqMap.get(qHash) ?? 0) * FIELD_WEIGHTS.headings +
          (f.urlTok.freqMap.get(qHash) ?? 0) * FIELD_WEIGHTS.url +
          (f.descTok.freqMap.get(qHash) ?? 0) * FIELD_WEIGHTS.description +
          (f.bodyTok.freqMap.get(qHash) ?? 0) * FIELD_WEIGHTS.body) /
        normFactor;

      if (pseudoTf <= 0) {
        continue;
      }

      const df = dfMap.get(qHash) ?? 0;
      // Robertson-Sparck Jones IDF with smoothing
      const idf = Math.log(1 + (N - df + 0.5) / (df + 0.5) + 0.5);
      const tfComponent = ((k1 + 1) * pseudoTf) / (k1 + pseudoTf) + delta;
      docBm25 += idf * tfComponent;
    }

    bm25RawScores[di] = docBm25;
    if (docBm25 > maxBm25) {
      maxBm25 = docBm25;
    }
    if (merged[di].rrfRaw > maxRrf) {
      maxRrf = merged[di].rrfRaw;
    }
  }

  // Stage 4: ColBERT Subword MaxSim + Proximity + Freshness/Authority
  const stage4Candidates = merged.map((entry, di) => {
    const rrfScore = maxRrf > 0 ? entry.rrfRaw / maxRrf : 0.5;
    const bm25fScore = maxBm25 > 0 ? bm25RawScores[di] / maxBm25 : 0;

    const { maxSimScore: passageMaxSimScore, highlights } =
      computePassageMaxSimAndHighlights(
        queryTok,
        rawQueryLower,
        entry.doc,
        maxHighlights
      );

    const proximityScore = computeProximityAndExactScore(
      queryTok,
      rawQueryLower,
      docFields[di].titleTok,
      docFields[di].descTok,
      (entry.doc.title || "").toLowerCase(),
      (entry.doc.description || "").toLowerCase()
    );

    const freshnessAuthorityScore = computeFreshnessAndAuthorityScore(
      entry.doc,
      entry.canonicalUrl
    );

    const hasUserLocation = Boolean(
      options.userLocation?.country ||
      options.userLocation?.city ||
      options.userLocation?.region
    );
    const geoAffinityScore = computeGeoAffinityScore(
      entry.doc,
      entry.canonicalUrl,
      options.userLocation,
      options.filterContext
    );

    // Strip trailing " - Publisher" or " | Publisher" before computing title dedup signature
    const cleanHeadline = (entry.doc.title || "")
      .replace(/\s+[-|–\u2014]\s+[^-|–\u2014]{2,50}$/, "")
      .trim();
    const cleanHeadlineTok = tokenizeAndHash(cleanHeadline);
    const queryHashSet = new Set<number>(queryTok.hashes);
    const nonQueryTitleHashes = new Set<number>(
      Array.from(cleanHeadlineTok.hashes).filter((h) => !queryHashSet.has(h))
    );

    // Dynamic filter penalties for agent-supplied `mustIncludeTerms` and `excludeTerms`
    let filterMultiplier = 1.0;
    const combinedLower =
      `${entry.doc.title || ""} ${entry.doc.description || ""} ${entry.canonicalUrl}`.toLowerCase();
    if (options.filterContext?.mustIncludeTerms?.length) {
      for (const reqTerm of options.filterContext.mustIncludeTerms) {
        const cleanTerm = reqTerm.trim().toLowerCase();
        if (cleanTerm && !combinedLower.includes(cleanTerm)) {
          filterMultiplier *= 0.55;
        }
      }
    }
    if (options.filterContext?.excludeTerms?.length) {
      for (const exTerm of options.filterContext.excludeTerms) {
        const cleanTerm = exTerm.trim().toLowerCase();
        if (cleanTerm && combinedLower.includes(cleanTerm)) {
          filterMultiplier *= 0.25;
        }
      }
    }

    // Calibrated Stage 1-4 Lexical + Structural + Geo Hybrid Score in [0, 1]
    const baseLexical =
      rrfScore * 0.22 +
      bm25fScore * 0.3 +
      passageMaxSimScore * 0.24 +
      proximityScore * 0.14 +
      freshnessAuthorityScore * 0.1;

    const geoWeight = hasUserLocation
      ? options.filterContext?.preferLocalDomains
        ? 0.22
        : 0.14
      : options.filterContext?.subcategory ||
          options.filterContext?.boostTerms?.length
        ? 0.1
        : 0;
    const lexicalHybridScore =
      (baseLexical * (1 - geoWeight) + geoAffinityScore * geoWeight) *
      filterMultiplier;

    return {
      entry,
      highlights,
      titleHashSet: new Set<number>(cleanHeadlineTok.hashes),
      nonQueryTitleHashes,
      signatureHashSet: new Set<number>([
        ...cleanHeadlineTok.hashes,
        ...docFields[di].descTok.hashes.slice(0, 24),
      ]),
      publisherKey: extractPublisherDomainKey(
        entry.canonicalUrl,
        entry.doc.title || "",
        entry.doc.description || ""
      ),
      breakdown: {
        rrfScore: Number(rrfScore.toFixed(4)),
        bm25fScore: Number(bm25fScore.toFixed(4)),
        passageMaxSimScore: Number(passageMaxSimScore.toFixed(4)),
        proximityScore: Number(proximityScore.toFixed(4)),
        freshnessAuthorityScore: Number(freshnessAuthorityScore.toFixed(4)),
        ...(hasUserLocation
          ? { geoAffinityScore: Number(geoAffinityScore.toFixed(4)) }
          : {}),
        lexicalHybridScore: Number(lexicalHybridScore.toFixed(4)),
        multiEngineConsensusCount: entry.sources.length,
      } as DocumentScoreBreakdown,
      finalScore: lexicalHybridScore,
    };
  });

  // Sort by Stage 1-4 score, then apply a light domain diversity pre-pass before Stage 5
  // so our Decision Model top-N budget isn't wasted scoring 3 pages from the same domain.
  stage4Candidates.sort((lhs, rhs) => rhs.finalScore - lhs.finalScore);
  const preDomainCounts = new Map<string, number>();
  for (const cand of stage4Candidates) {
    const prevCount = preDomainCounts.get(cand.publisherKey) ?? 0;
    if (prevCount > 0) {
      cand.finalScore *= Math.pow(0.84, prevCount);
    }
    preDomainCounts.set(cand.publisherKey, prevCount + 1);
  }
  stage4Candidates.sort((lhs, rhs) => rhs.finalScore - lhs.finalScore);
  const lexicalLatencyMs = Number((performance.now() - startTotal).toFixed(2));

  // Stage 5: Vercel AI Gateway Decision Model Reranking (`baseten/mammoth-1` / `convaiinnovations/laya`)
  let decisionLatencyMs = 0;
  let decisionModelUsed: string | null = null;

  if (
    useDecisionModel &&
    decisionModel !== "none" &&
    stage4Candidates.length > 0
  ) {
    const decisionStart = performance.now();
    const topSlice = stage4Candidates.slice(0, decisionTopN);
    const decisionOut = await runDecisionModelReranker(
      query,
      topSlice.map((c) => ({
        title: c.entry.doc.title || "",
        url: c.entry.canonicalUrl,
        description: c.entry.doc.description || "",
        highlights: c.highlights,
      })),
      decisionModel,
      decisionTimeoutMs,
      options.userLocation,
      options.filterContext
    );
    decisionLatencyMs = Number((performance.now() - decisionStart).toFixed(2));

    if (decisionOut && decisionOut.scores.size > 0) {
      decisionModelUsed = decisionOut.modelUsed;
      for (let i = 0; i < topSlice.length; i++) {
        const dScore = decisionOut.scores.get(i);
        if (dScore) {
          topSlice[i].breakdown.decisionScore = dScore.normalizedScore;
          topSlice[i].breakdown.decisionRawScore = dScore.rawScore;
          topSlice[i].breakdown.decisionConfidence = dScore.confidence;
          topSlice[i].breakdown.decisionModelUsed =
            decisionModelUsed || undefined;
          // Blend 52% Stage 1-4 IR hybrid + 48% Stage 5 Neural Decision Model probability score
          topSlice[i].finalScore =
            topSlice[i].breakdown.lexicalHybridScore * 0.52 +
            dScore.normalizedScore * 0.48;
        }
      }
      stage4Candidates.sort((lhs, rhs) => rhs.finalScore - lhs.finalScore);
    }
  }

  // Stage 6: Maximal Marginal Relevance (MMR) Near-Duplicate Suppression & optional Per-Domain Cap.
  // Distinct URLs from the same provider are distinct results (e.g. several listings on one
  // portal, several articles from one publisher), so there is no hard cap unless the caller
  // asks for one. A soft MMR decay still spreads providers when scores are close.
  const maxPerDomain = options.maxPerDomain ?? Number.POSITIVE_INFINITY;
  const mmrLambda = options.mmrLambda ?? 0.82;
  const selected: typeof stage4Candidates = [];
  const deferredOverflow: typeof stage4Candidates = [];
  const nearDuplicates: typeof stage4Candidates = [];
  const domainCounts = new Map<string, number>();
  const remaining = [...stage4Candidates];

  while (selected.length < topK && remaining.length > 0) {
    let bestIdx = -1;
    let bestMmrScore = -Infinity;

    for (let i = 0; i < remaining.length; i++) {
      const cand = remaining[i];

      // Check near-duplicate title or title+snippet similarity against already-selected results
      let maxSim = 0;
      let isHardNearDuplicate = false;
      for (const sel of selected) {
        const titleSim = computeTokenSimilarity(
          cand.titleHashSet,
          sel.titleHashSet
        );
        const sigSim = computeTokenSimilarity(
          cand.signatureHashSet,
          sel.signatureHashSet
        );
        const combinedSim = Math.max(titleSim * 0.95, sigSim);
        if (combinedSim > maxSim) {
          maxSim = combinedSim;
        }
        // Suppress syndicated copies (same story on a different publisher) with >= 0.72
        // title/snippet overlap. Same publisher + different URL is a distinct page
        // (e.g. two listings with templated titles) and is kept.
        if (
          cand.publisherKey !== sel.publisherKey &&
          (titleSim >= 0.75 || sigSim >= 0.72)
        ) {
          isHardNearDuplicate = true;
          break;
        }
      }

      if (isHardNearDuplicate) {
        // Defer (don't drop): backfilled with a penalty only if the pool runs short.
        nearDuplicates.push(cand);
        remaining.splice(i, 1);
        i--;
        continue;
      }

      const currentDomainCount = domainCounts.get(cand.publisherKey) ?? 0;
      if (currentDomainCount >= maxPerDomain) {
        deferredOverflow.push(cand);
        remaining.splice(i, 1);
        i--;
        continue;
      }

      const domainDecay = Math.pow(0.8, currentDomainCount);
      const mmrScore =
        mmrLambda * (cand.finalScore * domainDecay) - (1 - mmrLambda) * maxSim;

      if (mmrScore > bestMmrScore) {
        bestMmrScore = mmrScore;
        bestIdx = i;
      }
    }

    if (bestIdx === -1) {
      break;
    }

    const chosen = remaining.splice(bestIdx, 1)[0];
    const prevDomainCount = domainCounts.get(chosen.publisherKey) ?? 0;
    if (prevDomainCount > 0) {
      chosen.finalScore = Number(
        (chosen.finalScore * Math.pow(0.85, prevDomainCount)).toFixed(4)
      );
    }
    domainCounts.set(chosen.publisherKey, prevDomainCount + 1);
    selected.push(chosen);
  }

  // If strict domain cap left fewer than topK results and we have overflow candidates, backfill
  for (const overflow of deferredOverflow) {
    if (selected.length >= topK) {
      break;
    }
    const prevDomainCount = domainCounts.get(overflow.publisherKey) ?? 1;
    overflow.finalScore = Number(
      (overflow.finalScore * Math.pow(0.82, prevDomainCount)).toFixed(4)
    );
    domainCounts.set(overflow.publisherKey, prevDomainCount + 1);
    selected.push(overflow);
  }

  for (const dup of nearDuplicates) {
    if (selected.length >= topK) {
      break;
    }
    dup.finalScore = Number((dup.finalScore * 0.6).toFixed(4));
    selected.push(dup);
  }

  selected.sort((lhs, rhs) => rhs.finalScore - lhs.finalScore);

  const results: RankedDocument[] = selected
    .slice(0, topK)
    .map((item, idx) => ({
      title: item.entry.doc.title,
      url: item.entry.doc.url,
      canonicalUrl: item.entry.canonicalUrl,
      description: item.entry.doc.description,
      ...(item.entry.doc.markdown !== undefined
        ? { markdown: item.entry.doc.markdown }
        : {}),
      ...(item.entry.doc.links !== undefined
        ? { links: item.entry.doc.links }
        : {}),
      ...(item.entry.doc.publishedDate !== undefined
        ? { publishedDate: item.entry.doc.publishedDate }
        : {}),
      score: Number(item.finalScore.toFixed(4)),
      rank: idx + 1,
      sources: item.entry.sources,
      highlights: item.highlights,
      scoreBreakdown: item.breakdown,
    }));

  return {
    results,
    rankingMetrics: {
      totalCandidates: rawCandidates.length,
      uniqueCandidates: N,
      lexicalLatencyMs,
      decisionLatencyMs,
      totalRankingLatencyMs: Number(
        (performance.now() - startTotal).toFixed(2)
      ),
      decisionModelUsed,
      enginesContributing,
    },
  };
}
