/**
 * src/data/retriever.ts — Cluster-Diverse RAG with Security Briefing Synthesis
 *
 * Flow:
 *   1. Load K=10 cluster centroids
 *   2. Embed queryText (Protocol Map formatted string)
 *   3. Score query vs all centroids → pick top K=10 most relevant clusters
 *   4. From each cluster, fetch top 3 findings by similarity → 30 findings total
 *   5. Call small LLM to synthesize a 400-600 token Security Briefing
 *   6. Return briefing text to inject into audit prompt
 *
 * Fallback: if centroids missing or synthesis fails → plain similarity search
 *           → raw formatted findings (old behaviour, always works)
 */

import { existsSync } from "fs";
import { mkdir, readFile, writeFile } from "fs/promises";
import { join } from "path";
import type { Document } from "@langchain/core/documents";
import { SystemMessage, HumanMessage } from "@langchain/core/messages";
import { getVectorStore } from "./vector-store.js";
import { makeEmbeddingsModel, buildCartographyModel } from "../utils/models.js";
import { env } from "../utils/env.js";
import { logger } from "../utils/logger.js";
import { ChatOllama } from "@langchain/ollama";

import { buildAuditorModel } from "../utils/models.js";

import type { EngineConfig } from "../types/protocol.js";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface ClusterCentroid {
  clusterId: number;
  label: string;
  vector: number[];
  size: number;
}

const synthesisPath = join(process.cwd(), "output", "rag-synthesis.md");

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Main entry point. Returns the Security Briefing string to inject into prompts.
 *
 * @param queryText  Protocol Map formatted string — describes the codebase
 * @param config     Engine config — needed to build the synthesis model
 * @param k          Number of clusters to use (default 10, matches K in cluster script)
 */
export async function fetchClusterDiverseFindings(
  queryText: string,
  config?: EngineConfig,
  k = 10, // 10 clusters, as this was used to create the centroids
): Promise<string> {
  const store = await getVectorStore();
  const centroids = await loadCentroids();

  if (centroids.length === 0) {
    logger.warn(
      "retriever",
      "No centroids found — using plain similarity search",
    );
    return plainSearch(store, queryText, k);
  }

  // Get top-3 from top-k clusters = up to 30 findings
  const rawFindings = await clusterDiverseSearch(
    store,
    queryText,
    centroids,
    k,
    3, // top 3 findings from each cluster
  );

  if (rawFindings.length === 0) {
    logger.warn(
      "retriever",
      "Cluster search returned no results — falling back",
    );
    return plainSearch(store, queryText, k);
  }

  logger.info(
    "retriever",
    `Retrieved ${rawFindings.length} findings from ${Math.min(k, centroids.length)} clusters`,
  );

  // Synthesize if we have a config (engine context) — skip in tests/scripts
  if (config) {
    const briefing = await synthesizeSecurityBriefing(
      rawFindings,
      queryText,
      config,
    );
    if (briefing) {
      logger.info(
        "[retriever]",
        "Synthesized Security Briefing written to file",
      );

      await mkdir(join(process.cwd(), "output"), { recursive: true });
      await writeFile(synthesisPath, briefing, "utf-8");
      return briefing;
    }
  }

  // Fallback: return raw formatted findings
  return formatRawFindings(rawFindings);
}

// ─── Cluster-Diverse Search ───────────────────────────────────────────────────

async function clusterDiverseSearch(
  store: any,
  queryText: string,
  centroids: ClusterCentroid[],
  numClusters: number,
  topPerCluster: number,
): Promise<Array<{ label: string; doc: Document; score: number }>> {
  const embeddings = makeEmbeddingsModel();
  const querySlice = queryText.slice(0, 4000);
  const queryVector = await embeddings.embedQuery(querySlice);

  // Score query against all centroids, pick top numClusters
  const topClusters = centroids
    .map(c => ({ ...c, similarity: cosineSimilarity(queryVector, c.vector) }))
    .sort((a, b) => b.similarity - a.similarity)
    .slice(0, numClusters);

  logger.debug("retriever", "Top clusters", {
    clusters: topClusters
      .map(c => `${c.label}(${c.similarity.toFixed(3)})`)
      .join(", "),
  });

  // For each top cluster: get top topPerCluster findings by similarity
  const results: Array<{ label: string; doc: Document; score: number }> = [];

  await Promise.all(
    topClusters.map(async ({ clusterId, label }) => {
      try {
        // similaritySearchWithScore returns [doc, score][] — filter by clusterId
        const docsWithScore: [Document, number][] =
          await store.similaritySearchWithScore(
            querySlice,
            topPerCluster,
            (doc: Document) => doc.metadata?.clusterId === clusterId,
          );
        for (const [doc, score] of docsWithScore) {
          results.push({ label, doc, score });
        }
      } catch {
        // Individual cluster failure is non-fatal
      }
    }),
  );

  // Sort by score (similarity) descending
  return results.sort((a, b) => b.score - a.score);
}

// ─── Security Briefing Synthesis ──────────────────────────────────────────────

/**
 * Synthesizes 30 raw findings into a focused Security Briefing (400-600 tokens).
 *
 * The briefing tells the auditor:
 *   - Which vulnerability classes are most relevant for this codebase type
 *   - Specific patterns to look for given this protocol's entry points
 *   - Historical examples of how similar protocols have been exploited
 *
 * This is more useful than dumping raw markdown excerpts because:
 *   - 9B models understand curated guidance better than reference material
 *   - The synthesis connects historical patterns to THIS codebase specifically
 *   - 400 tokens vs 4800 tokens = more room for contract code
 */
async function synthesizeSecurityBriefing(
  findings: Array<{ label: string; doc: Document; score: number }>,
  protocolMapSnippet: string,
  config: EngineConfig,
): Promise<string | null> {
  try {
    // Build synthesis model — same as cartography but with more output tokens
    // Uses auditor-1 machine/model, temperature 0
    const model = buildSynthesisModel(config);

    // Format the 30 findings compactly — each capped at 300 chars
    const findingSummaries = findings
      .slice(0, 30)
      .map((f, i) => {
        const severity = f.doc.metadata?.severity ?? "Unknown";
        const protocol = f.doc.metadata?.protocol ?? "Unknown";
        const excerpt = f.doc.pageContent.slice(0, 300).replace(/\n+/g, " ");
        return `[${i + 1}] ${f.label} | ${severity} | ${protocol}\n${excerpt}`;
      })
      .join("\n\n");

    // Protocol map snippet — first 1000 chars is enough for context
    const mapSnippet = protocolMapSnippet.slice(0, 3000);

    const systemPrompt = `You are a smart contract security analyst. Your task is to synthesize multiple historical vulnerability findings from similar protocols into a single, concise **Security Briefing** for an auditor.

You will be given:
- A protocol map (entry points, state variables, interactions)
- A list of vulnerability findings (each with a title, severity, description, and category)

Your output must be **plain text** (no markdown headers, no JSON, no code fences). Structure it exactly as follows:

[ROOT CAUSE SUMMARY]
A single paragraph (2–4 sentences) that explains the most common root cause across the findings, referencing the protocol's architecture.

[VULNERABILITY CLASSES & PATTERNS]
For the most relevant vulnerability classes (e.g., reentrancy, access control, oracle manipulation, arithmetic issues, token approval, etc.):
You can merge the classes if they have a common root cause. For each class, list the patterns, like a human would interpret and that the auditor should look for in the codebase, especially in relation to the protocol's entry points and interactions
- **Class Name**: 1-sentence description of the class.
  - **Pattern to look for**: Specific code pattern (e.g., "external call before state update", "missing onlyOwner modifier", "spot price used for liquidation").
      - Again, you can merge patterns if they have a common root cause. Focus on patterns that are relevant to the protocol's entry points and interactions and the ones that can lead to novelty bugs.
  - **Relevant entry points**: List actual function names from the protocol map (e.g., deposit(), withdraw(), claim()).

[CONCRETE EXPLOIT SCENARIO]
One clear, step‑by‑step scenario 5-7 steps max that combines the most dangerous pattern with the protocol's actual entry points for "How a vulnerability could be exploited using the knowledge and patterns at hand". Use a numbered list.

Do not add any preamble or extra commentary. Keep the total output under 800 words. The output should strictly mirror the attacker's mindset and not the particular bug or syntax itself`;

    const userPrompt = `Protocol being audited (entry points and structure):
${mapSnippet}

Historical vulnerability findings from similar protocols (${findings.length} findings across clusters):
${findingSummaries}

Now produce the Security Briefing as specified.`;

    const response = await model.invoke([
      new SystemMessage(systemPrompt),
      new HumanMessage(userPrompt),
    ]);

    const text = extractContentString(response.content);
    if (!text || text.length < 50) return null;

    logger.info(
      "retriever",
      `Security Briefing synthesized (${text.length} chars)`,
    );

    return [
      "=== SECURITY BRIEFING (synthesized from historical findings) ===",
      "",
      text.trim(),
      "",
      "===",
    ].join("\n");
  } catch (err) {
    console.error(`[retriever error]`, err);
    logger.warn("retriever", "Synthesis failed — using raw findings", {
      error: (err as Error).message,
    });
    return null;
  }
}

// ─── Plain Search Fallback ────────────────────────────────────────────────────

async function plainSearch(
  store: any,
  queryText: string,
  k: number,
): Promise<string> {
  const results: Document[] = await store.similaritySearch(
    queryText.slice(0, 4000),
    k,
  );
  return formatRawFindings(
    results.map(doc => ({
      label: String(doc.metadata?.category ?? "unknown"),
      doc,
      score: 0,
    })),
  );
}

// ─── Formatting ───────────────────────────────────────────────────────────────

function formatRawFindings(
  results: Array<{ label: string; doc: Document; score?: number }>,
): string {
  if (results.length === 0)
    return "No relevant past vulnerability findings retrieved.";

  const lines: string[] = [
    `${results.length} relevant vulnerability patterns from Solodit audit database:`,
    "",
  ];

  results.slice(0, 15).forEach(({ label, doc }, i) => {
    const severity = doc.metadata?.severity ?? "Unknown";
    const protocol = doc.metadata?.protocol ?? "Unknown";
    lines.push(
      `[Finding ${i + 1}] Category: ${label} | Severity: ${severity} | Protocol: ${protocol}`,
    );
    lines.push(doc.pageContent.slice(0, 400));
    lines.push("");
  });

  return lines.join("\n");
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

async function loadCentroids(): Promise<ClusterCentroid[]> {
  const centroidsFile = join(env.DATA_DIR, "clusters", "centroids.json");
  if (!existsSync(centroidsFile)) return [];
  try {
    const raw = await readFile(centroidsFile, "utf-8");
    return JSON.parse(raw) as ClusterCentroid[];
  } catch (err) {
    logger.warn("retriever", "Could not load centroids", {
      error: (err as Error).message,
    });
    return [];
  }
}

function cosineSimilarity(a: number[], b: number[]): number {
  if (a.length !== b.length) return 0;
  let dot = 0,
    magA = 0,
    magB = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    magA += a[i] * a[i];
    magB += b[i] * b[i];
  }
  const denom = Math.sqrt(magA) * Math.sqrt(magB);
  return denom === 0 ? 0 : dot / denom;
}

function extractContentString(content: unknown): string {
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    return content
      .map(b => (typeof b === "string" ? b : ((b as any)?.text ?? "")))
      .join("");
  }
  return String(content);
}

/**
 * Build the synthesis model — same machine/provider as auditor-1 but tuned
 * for synthesis: temperature 0, more output tokens, bigger context for 30 findings.
 */
function buildSynthesisModel(config: EngineConfig) {
  const auditor1 = config.auditors[0];

  if (auditor1.provider === "ollama" || !auditor1.provider) {
    return new ChatOllama({
      model: auditor1.model,
      baseUrl: auditor1.ollamaBaseUrl ?? env.OLLAMA_BASE_URL,
      temperature: 0.0,
      numCtx: 16384, // needs to hold 30 findings
      think: false, // synthesis is extraction, not reasoning, no thinking tokens // TODO: change this and also test
      streaming: false,
      disableStreaming: true,
      seed: 40,
    });
  }

  // Cloud providers: use buildAuditorModel which handles all providers
  return buildAuditorModel(auditor1, 0);
}
