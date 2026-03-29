import { existsSync } from "fs";
import { readFile } from "fs/promises";
import { join } from "path";
import type { Document } from "@langchain/core/documents";
import { getVectorStore } from "./vector-store.js";
import { makeEmbeddingsModel } from "../utils/models.js";
import { env } from "../utils/env.js";
import { logger } from "../utils/logger.js";
import type { SolidityFile } from "../types/recon.js";

// ─── Cluster Centroid Types ───────────────────────────────────────────────────

export interface ClusterCentroid {
  clusterId: number;
  label: string; // e.g. "reentrancy", "oracle-manipulation"
  vector: number[];
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Fetch diverse vulnerability findings relevant to the given contracts.
 *
 * Returns up to `k` findings — one per vulnerability cluster.
 * Each finding comes from a different cluster, ensuring the agents
 * see patterns from multiple vulnerability classes, not just the nearest class.
 *
 * Falls back to plain similarity search if clustering hasn't run yet.
 */
export async function fetchClusterDiverseFindings(
  files: SolidityFile[],
  k: number = 6,
): Promise<string> {
  const store = await getVectorStore();
  const combinedCode = files.map(f => f.content).join("\n\n");

  // Try cluster-aware retrieval first
  const centroids = await loadCentroids();
  if (centroids.length > 0) {
    return clusterAwareSearch(store, combinedCode, centroids, k);
  }

  // Fallback: plain similarity search (before clustering has run)
  logger.warn(
    "retriever",
    "Cluster data not found — using plain similarity search. Run npm run cluster for better results.",
  );
  return plainSearch(store, combinedCode, k);
}

// ─── Cluster-Aware Search ─────────────────────────────────────────────────────

async function clusterAwareSearch(
  store: HNSWLib,
  contractCode: string,
  centroids: ClusterCentroid[],
  k: number,
): Promise<string> {
  // Embed the contract code as a query vector
  const embeddings = makeEmbeddingsModel();
  const queryVector = await embeddings.embedQuery(contractCode);

  // Score the query against all cluster centroids
  const scored = centroids
    .map(c => ({
      ...c,
      similarity: cosineSimilarity(queryVector, c.vector),
    }))
    .sort((a, b) => b.similarity - a.similarity)
    .slice(0, k);

  logger.debug("retriever", "Top clusters by similarity", {
    clusters: scored.map(c => `${c.label} (${c.similarity.toFixed(3)})`),
  });

  // From each top cluster, retrieve the single best matching finding
  const results = await Promise.all(
    scored.map(async ({ clusterId, label }) => {
      const docs = await store.similaritySearch(
        contractCode,
        1,
        // HNSWLib filter: function called on each doc during search
        (doc: Document) => doc.metadata?.clusterId === clusterId,
      );
      return { clusterId, label, doc: docs[0] ?? null };
    }),
  );

  const validResults = results.filter(r => r.doc !== null);

  if (validResults.length === 0) {
    logger.warn(
      "retriever",
      "Cluster search returned no results, falling back to plain search",
    );
    return plainSearch(store, contractCode, k);
  }

  return formatRagContext(
    validResults.map(r => ({ label: r.label, doc: r.doc! })),
  );
}

// ─── Plain Search Fallback ────────────────────────────────────────────────────

async function plainSearch(
  store: HNSWLib,
  contractCode: string,
  k: number,
): Promise<string> {
  const results = await store.similaritySearch(contractCode, k);
  return formatRagContext(
    results.map(doc => ({
      label: String(doc.metadata?.category ?? "unknown"),
      doc,
    })),
  );
}

// ─── Formatting ───────────────────────────────────────────────────────────────

function formatRagContext(
  results: Array<{ label: string; doc: Document }>,
): string {
  if (results.length === 0) {
    return "No relevant past vulnerability findings retrieved.";
  }

  const lines: string[] = [
    `${results.length} relevant vulnerability patterns from Solodit audit database:`,
    "",
  ];

  results.forEach(({ label, doc }, i) => {
    const severity = doc.metadata?.severity ?? "Unknown";
    const protocol = doc.metadata?.protocol ?? "Unknown";
    lines.push(
      `[Finding ${i + 1}] Category: ${label} | Severity: ${severity} | Protocol: ${protocol}`,
    );
    // Trim each finding to ~200 tokens worth of text
    const preview = doc.pageContent.slice(0, 800);
    lines.push(preview);
    lines.push("");
  });

  return lines.join("\n");
}

// ─── Centroid Loading ─────────────────────────────────────────────────────────

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

// ─── Math ─────────────────────────────────────────────────────────────────────

function cosineSimilarity(a: number[], b: number[]): number {
  if (a.length !== b.length) return 0;
  let dot = 0;
  let magA = 0;
  let magB = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    magA += a[i] * a[i];
    magB += b[i] * b[i];
  }
  const denom = Math.sqrt(magA) * Math.sqrt(magB);
  return denom === 0 ? 0 : dot / denom;
}

// HNSWLib import needed for the filter callback type
import type { HNSWLib } from "@langchain/community/vectorstores/hnswlib";
