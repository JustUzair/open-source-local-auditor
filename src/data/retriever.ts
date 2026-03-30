import { existsSync } from "fs";
import { readFile } from "fs/promises";
import { join } from "path";
import type { Document } from "@langchain/core/documents";
import { getVectorStore } from "./vector-store.js";
import { makeEmbeddingsModel } from "../utils/models.js";
import { env } from "../utils/env.js";
import { logger } from "../utils/logger.js";
import { HNSWLib } from "@langchain/community/vectorstores/hnswlib";

export interface ClusterCentroid {
  clusterId: number;
  label: string;
  vector: number[];
  size: number;
}

// export async function fetchClusterDiverseFindings(
//   queryText: string,
//   k: number = 6,
// ): Promise<string> {
//   const store = await getVectorStore();
//   const centroids = await loadCentroids();

//   if (centroids.length > 0)
//     return clusterAwareSearch(store, queryText, centroids, k);

//   logger.warn(
//     "retriever",
//     "Cluster data not found — using plain similarity search.",
//   );
//   return plainSearch(store, queryText, k);
// }
export async function fetchRelevantFindings(
  queryText: string,
  k: number = 8,
): Promise<string> {
  const store = await getVectorStore();
  // Trim to the most signal-dense part of the protocol map:
  // function names, state vars, value flows — first ~2000 chars is usually best
  const query = queryText.slice(0, 3000);
  return plainSearch(store, query, k);
}

async function clusterAwareSearch(
  store: HNSWLib,
  queryText: string,
  centroids: ClusterCentroid[],
  k: number,
): Promise<string> {
  const embeddings = makeEmbeddingsModel();
  const querySlice = queryText.slice(0, 6000);
  const queryVector = await embeddings.embedQuery(querySlice);

  const scored = centroids
    .map(c => ({ ...c, similarity: cosineSimilarity(queryVector, c.vector) }))
    .sort((a, b) => b.similarity - a.similarity)
    .slice(0, k);

  logger.debug("retriever", "Top clusters by similarity", {
    clusters: scored.map(c => `${c.label} (${c.similarity.toFixed(3)})`),
  });

  const results = await Promise.all(
    scored.map(async ({ clusterId, label }) => {
      // #TODO This needs to be refined as it fetches only generic findings
      const docs = await store.similaritySearchWithScore(
        querySlice,
        k,
        (doc: Document) => doc.metadata?.clusterId === clusterId,
      );
      return { clusterId, label, doc: docs[0]?.[0] ?? null };
    }),
  );

  const validResults = results.filter(r => r.doc !== null);
  if (validResults.length === 0) return plainSearch(store, queryText, k);

  return formatRagContext(
    validResults.map(r => ({ label: r.label, doc: r.doc! })),
  );
}

async function plainSearch(
  store: any,
  queryText: string,
  k: number,
): Promise<string> {
  const results = await store.similaritySearch(queryText.slice(0, 4000), k);
  return formatRagContext(
    results.map((doc: Document) => ({
      label: String(doc.metadata?.category ?? "unknown"),
      doc,
    })),
  );
}

function formatRagContext(
  results: Array<{ label: string; doc: Document }>,
): string {
  if (results.length === 0)
    return "No relevant past vulnerability findings retrieved.";
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
    lines.push(doc.pageContent.slice(0, 800));
    lines.push("");
  });
  return lines.join("\n");
}

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
