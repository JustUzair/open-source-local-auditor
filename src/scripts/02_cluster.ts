import { readFile, writeFile, mkdir } from "fs/promises";
import { existsSync } from "fs";
import { join } from "path";
import { createReadStream } from "fs";
import { createInterface as rlInterface } from "readline";
import dotenv from "dotenv";
import { kmeans } from "ml-kmeans";
import type { Document } from "@langchain/core/documents";
import { HNSWLib } from "@langchain/community/vectorstores/hnswlib";
import { makeEmbeddingsModel, makeSupervisorModel } from "../utils/models.js";
import { invokeWithSchema } from "../utils/llm.js";
import { env } from "../utils/env.js";
import { logger } from "../utils/logger.js";
import { readCheckpoint, writeCheckpoint } from "../data/checkpoint.js";
import { storePath, resetVectorStoreCache } from "../data/vector-store.js";
import { z } from "zod";

dotenv.config();

// ─── Config ───────────────────────────────────────────────────────────────────

const DATA_DIR = env.DATA_DIR;
const EMBEDDINGS_FILE = join(DATA_DIR, "embeddings-raw.jsonl");
const CLUSTERS_DIR = join(DATA_DIR, "clusters");
const CENTROIDS_FILE = join(CLUSTERS_DIR, "centroids.json");

/**
 * Number of clusters. 35 was chosen to match the ~30 distinct vulnerability
 * classes in Solodit while allowing some sub-class granularity.
 */
const K = 35;

// ─── Types ────────────────────────────────────────────────────────────────────

interface EmbeddingRecord {
  docIndex: number;
  embedding: number[];
  category: string;
}

interface ClusterCentroid {
  clusterId: number;
  label: string;
  vector: number[];
  size: number;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Read all records from the JSONL embeddings file. */
async function readEmbeddingRecords(): Promise<EmbeddingRecord[]> {
  if (!existsSync(EMBEDDINGS_FILE)) {
    throw new Error(
      `Embeddings file not found: ${EMBEDDINGS_FILE}\nRun npm run ingest first.`,
    );
  }

  const records: EmbeddingRecord[] = [];
  const rl = rlInterface({
    input: createReadStream(EMBEDDINGS_FILE),
    crlfDelay: Infinity,
  });

  for await (const line of rl) {
    if (line.trim()) {
      records.push(JSON.parse(line));
    }
  }

  return records;
}

/** Auto-label a cluster by asking the LLM to summarize its top 3 documents. */
async function autoLabelCluster(
  clusterId: number,
  sampleDocs: Document[],
): Promise<string> {
  const LabelSchema = z.object({ label: z.string().min(3).max(50) });
  (LabelSchema as any)._example = { label: "oracle-price-manipulation" };

  const model = makeSupervisorModel();
  const sampleText = sampleDocs
    .slice(0, 3)
    .map(d => d.pageContent.slice(0, 300))
    .join("\n---\n");

  const result = await invokeWithSchema({
    model,
    systemPrompt:
      "You are a smart contract security expert. Given vulnerability findings, " +
      "output a short snake_case label for their common vulnerability class.",
    userPrompt: `Label this vulnerability cluster (cluster ${clusterId}) based on these sample findings:\n\n${sampleText}`,
    schema: LabelSchema,
    stage: `cluster-label-${clusterId}`,
    maxRetries: 0,
  });

  if (result.ok) return result.data.label;
  // Fallback: use the most common category from samples
  return sampleDocs[0]?.metadata?.category ?? `cluster-${clusterId}`;
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  console.log("\n🔵  SentinelAI — K-Means Clustering\n");

  if (!existsSync(CLUSTERS_DIR)) {
    await mkdir(CLUSTERS_DIR, { recursive: true });
  }

  // ── Load embeddings ────────────────────────────────────────────────────
  console.log("📖  Reading embedding records...");
  const records = await readEmbeddingRecords();
  console.log(`   ${records.length} embedding records loaded\n`);

  if (records.length < K) {
    throw new Error(
      `Too few embeddings (${records.length}) for K=${K} clusters. ` +
        `Need at least ${K}. Run more ingest first.`,
    );
  }

  // ── Run k-means ────────────────────────────────────────────────────────
  console.log(`🔵  Running k-means with K=${K}...`);
  const vectors = records.map(r => r.embedding);
  const result = kmeans(vectors, K, { initialization: "kmeans++" });
  console.log(`   Done. Iterations: ${result.iterations ?? "unknown"}\n`);

  // ── Load existing HNSWLib store to rebuild with cluster IDs ───────────
  console.log("📂  Loading vector store to add cluster IDs...");
  const dir = storePath();
  if (!existsSync(join(dir, "hnswlib.index"))) {
    throw new Error(
      `Vector store not found at ${dir}. Run npm run ingest first.`,
    );
  }

  const embeddings = makeEmbeddingsModel();
  const existingStore = await HNSWLib.load(dir, embeddings);

  // Get all documents from the docstore
  // HNSWLib's internal docstore is accessible via the memoryVectors property
  // We rebuild the store with cluster IDs added to metadata
  const allDocs: Document[] = [];
  const allVectors: number[][] = [];

  for (let i = 0; i < records.length; i++) {
    const record = records[i];
    const clusterId = result.clusters[i];

    // Try to get the original document from the store
    // HNSWLib stores docs in order of insertion
    try {
      const doc = (existingStore as any).docstore._docs.get(String(i));
      if (doc) {
        const docWithCluster = new (
          await import("@langchain/core/documents")
        ).Document({
          pageContent: doc.pageContent,
          metadata: {
            ...doc.metadata,
            clusterId,
          },
        });
        allDocs.push(docWithCluster);
        allVectors.push(record.embedding);
      }
    } catch {
      // Skip if doc not found at this index
    }
  }

  // ── Rebuild the store with cluster IDs ─────────────────────────────────
  console.log(
    `📦  Rebuilding index with cluster metadata (${allDocs.length} docs)...`,
  );
  const newStore = await HNSWLib.fromDocuments(allDocs.slice(0, 1), embeddings);
  if (allDocs.length > 1) {
    await newStore.addVectors(allVectors.slice(1), allDocs.slice(1));
  }
  await newStore.save(dir);
  resetVectorStoreCache();
  console.log("   ✅  Store rebuilt with cluster IDs\n");

  // ── Compute centroids and auto-label clusters ──────────────────────────
  console.log("🏷️   Auto-labelling clusters (LLM call per cluster)...");
  const centroids: ClusterCentroid[] = [];

  for (let clusterId = 0; clusterId < K; clusterId++) {
    const centroidVector = result.centroids[clusterId];
    const clusterDocIndices = records
      .map((_, i) => i)
      .filter(i => result.clusters[i] === clusterId);
    const clusterSize = clusterDocIndices.length;

    // Sample up to 3 docs for labelling
    const sampleDocs = clusterDocIndices
      .slice(0, 3)
      .map(i => allDocs[i])
      .filter(Boolean);

    const label =
      sampleDocs.length > 0
        ? await autoLabelCluster(clusterId, sampleDocs)
        : `cluster-${clusterId}`;

    centroids.push({
      clusterId,
      label,
      vector: Array.from(centroidVector),
      size: clusterSize,
    });

    process.stdout.write(
      `   Cluster ${clusterId}: ${label} (${clusterSize} docs)\n`,
    );
  }

  await writeFile(CENTROIDS_FILE, JSON.stringify(centroids, null, 2), "utf-8");

  // ── Update checkpoint ─────────────────────────────────────────────────
  const checkpoint = await readCheckpoint();
  if (checkpoint) {
    checkpoint.clustered = true;
    await writeCheckpoint(checkpoint);
  }

  console.log(`\n✅  Clustering complete`);
  console.log(`   K=${K} clusters labelled`);
  console.log(`   Centroids saved to: ${CENTROIDS_FILE}\n`);
  console.log(
    `Setup complete. Run an audit:\n  npm run sentinel -- audit ./contracts/\n`,
  );
}

main().catch(err => {
  console.error("\nClustering failed:", err);
  process.exit(1);
});
