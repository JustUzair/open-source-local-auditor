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

/**
 * Auto-label a cluster by asking the LLM to summarize its top documents.
 *
 * Strategy:
 *  1. Attempt 1 — larger sample (5 docs × 500 chars), hard uniqueness constraint
 *     baked into the Zod schema description, "FORBIDDEN" labels in prompt.
 *  2. Attempt 2 — differentiation prompt: explicitly tells the LLM what label
 *     it duplicated and asks it to find the mechanistic distinction using a
 *     fresh doc slice (docs 2–7, no overlap with attempt 1).
 *  3. Fallback — keyword extraction from sample text appended as a sub-class
 *     qualifier. Guarantees uniqueness without an additional API call.
 */
async function autoLabelCluster(
  clusterId: number,
  sampleDocs: Document[],
  usedLabels: Set<string>,
): Promise<string> {
  const model = makeSupervisorModel();
  const usedArray = Array.from(usedLabels);

  // ── Attempt 1: standard label generation ──────────────────────────────────
  // 5 docs × 500 chars — significantly more signal than the original 3 × 300.
  const sampleText = sampleDocs
    .slice(0, 5)
    .map((d, i) => `[Sample ${i + 1}]\n${d.pageContent.slice(0, 500)}`)
    .join("\n---\n");

  const LabelSchema = z.object({
    label: z
      .string()
      .min(3)
      .max(60)
      .describe(
        `A unique snake_case vulnerability class label. ` +
          `MUST NOT be any of these already-used labels: [${usedArray.join(", ")}]. ` +
          `Be specific — prefer sub-class labels like 'erc4626_inflation_attack' ` +
          `over broad ones like 'inflation_attack'.`,
      ),
    rationale: z
      .string()
      .max(150)
      .describe(
        "One sentence: what mechanistically distinguishes this cluster from similar ones.",
      ),
  });

  const systemPrompt =
    "You are a smart contract security researcher specializing in vulnerability taxonomy. " +
    "Your job is to assign a precise, unique snake_case label to a cluster of related audit findings. " +
    "Labels must be specific sub-classes, not broad categories. " +
    "For example, prefer 'erc4626_share_inflation' over 'inflation_attack', " +
    "'twap_oracle_stale_price' over 'oracle_price_manipulation', " +
    "'reentrancy_via_erc777_hook' over 'reentrancy', " +
    "'missing_deadline_check' over 'invalid_input_validation'. " +
    "Output ONLY the JSON object — no explanation outside the JSON.";

  const userPromptBase =
    `Assign a unique vulnerability class label to cluster ${clusterId}.\n\n` +
    `Sample findings from this cluster:\n${sampleText}\n\n` +
    (usedArray.length > 0
      ? `FORBIDDEN labels (already used for other clusters — your label MUST differ from ALL of these):\n` +
        `${usedArray.join(", ")}\n\n`
      : "") +
    `Output a specific sub-class label that precisely distinguishes this cluster.`;

  const attempt1 = await invokeWithSchema({
    model,
    systemPrompt,
    userPrompt: userPromptBase,
    schema: LabelSchema,
    stage: `cluster-label-${clusterId}-attempt1`,
    maxRetries: 1,
  });

  if (attempt1.ok && !usedLabels.has(attempt1.data.label)) {
    return attempt1.data.label;
  }

  // ── Attempt 2: explicit differentiation prompt ────────────────────────────
  // The LLM returned a duplicate. Give it fresh samples (different slice)
  // and explicitly ask it to find the mechanistic distinction.
  const conflictLabel = attempt1.ok ? attempt1.data.label : "(failed)";

  // Docs 2–7: intentional non-overlap with attempt 1's slice (0–4)
  const contrastText = sampleDocs
    .slice(2, 7)
    .map((d, i) => `[Contrast Sample ${i + 1}]\n${d.pageContent.slice(0, 400)}`)
    .join("\n---\n");

  const userPromptDifferentiate =
    `You suggested "${conflictLabel}" for cluster ${clusterId}, ` +
    `but that label is already taken by a different cluster.\n\n` +
    `Here are additional samples from cluster ${clusterId} — a different slice to help you find what is unique:\n` +
    `${contrastText}\n\n` +
    `FORBIDDEN labels: ${usedArray.join(", ")}\n\n` +
    `Focus on what is MECHANISTICALLY DISTINCT about this cluster: ` +
    `the specific code pattern, protocol mechanism, or exploit vector that separates it ` +
    `from the already-labelled clusters. Use that distinguishing trait as the label.`;

  const attempt2 = await invokeWithSchema({
    model,
    systemPrompt,
    userPrompt: userPromptDifferentiate,
    schema: LabelSchema,
    stage: `cluster-label-${clusterId}-attempt2`,
    maxRetries: 1,
  });

  if (attempt2.ok && !usedLabels.has(attempt2.data.label)) {
    return attempt2.data.label;
  }

  // ── Forced suffix fallback ────────────────────────────────────────────────
  // Both LLM attempts produced a duplicate. Extract the most distinguishing
  // keyword from the sample text and append as a sub-class qualifier.
  // Guarantees uniqueness without another API call.
  const baseLabel =
    attempt2.ok
      ? attempt2.data.label
      : attempt1.ok
        ? attempt1.data.label
        : sampleDocs[0]?.metadata?.category ?? `cluster`;

  // Strip any trailing numeric suffix from a previously-suffixed fallback
  const cleanBase = baseLabel.replace(/_\d+$/, "");

  const distinguishingKeywords = [
    "callback", "hook", "flash_loan", "delegatecall", "proxy", "permit",
    "signature", "deadline", "slippage", "rounding", "truncation", "overflow",
    "underflow", "sandwich", "frontrun", "backrun", "mev", "governance",
    "timelock", "multisig", "pausable", "upgrade", "initializer", "storage",
    "slot", "collision", "shadowing", "assembly", "selfdestruct", "create2",
    "cross_chain", "bridge", "relayer", "sequencer", "l2", "rollup",
    "erc20", "erc721", "erc1155", "erc4626", "erc777", "erc2612",
    "twap", "chainlink", "pyth", "uniswap", "balancer", "curve", "aave",
    "compound", "yield", "vault", "pool", "pair", "router", "factory",
  ];

  const rawText = sampleDocs
    .slice(0, 5)
    .map(d => d.pageContent.toLowerCase())
    .join(" ");

  const distinguisher = distinguishingKeywords.find(
    kw =>
      rawText.includes(kw.replace(/_/g, "")) &&
      !cleanBase.includes(kw.replace(/_/g, "")),
  );

  const fallbackLabel = distinguisher
    ? `${cleanBase}_${distinguisher}`
    : `${cleanBase}_${clusterId}`;

  logger.warn(
    "cluster",
    `Cluster ${clusterId}: LLM returned duplicate "${baseLabel}" on both attempts — ` +
      `using fallback "${fallbackLabel}"`,
  );

  return fallbackLabel;
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

  // Get all documents from the docstore and rebuild with cluster IDs
  const allDocs: Document[] = [];
  const allVectors: number[][] = [];

  for (let i = 0; i < records.length; i++) {
    const record = records[i];
    const clusterId = result.clusters[i];

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
  const usedLabels = new Set<string>();

  for (let clusterId = 0; clusterId < K; clusterId++) {
    const centroidVector = result.centroids[clusterId];
    const clusterDocIndices = records
      .map((_, i) => i)
      .filter(i => result.clusters[i] === clusterId);
    const clusterSize = clusterDocIndices.length;

    // Sample up to 7 docs — attempt 1 uses slice 0–4, attempt 2 uses slice 2–6,
    // giving each attempt a fresh perspective on the cluster contents.
    const sampleDocs = clusterDocIndices
      .slice(0, 7)
      .map(i => allDocs[i])
      .filter(Boolean);

    const label =
      sampleDocs.length > 0
        ? await autoLabelCluster(clusterId, sampleDocs, usedLabels)
        : `cluster-${clusterId}`;

    usedLabels.add(label);

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