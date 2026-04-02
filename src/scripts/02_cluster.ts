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
import { ChatOllama } from "@langchain/ollama";

dotenv.config();

// ─── Config ───────────────────────────────────────────────────────────────────

const DATA_DIR = env.DATA_DIR;
const EMBEDDINGS_FILE = join(DATA_DIR, "embeddings-raw.jsonl");
const CLUSTERS_DIR = join(DATA_DIR, "clusters");
const CENTROIDS_FILE = join(CLUSTERS_DIR, "centroids.json");

/**
 * Number of clusters. 35 was chosen initially to match the ~30 distinct vulnerability
 * classes in Solodit while allowing some sub-class granularity.
 *
 * UPDATE: Use 10 clusters only to broaden the category of findings in each cluster and prevent overfitting
 */
const K = 10;

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
  const model = new ChatOllama({
    baseUrl: env.SUPERVISOR_OLLAMA_URL ?? env.OLLAMA_BASE_URL,
    model: env.SUPERVISOR_MODEL,
    temperature: 0.1,
    think: false,
    streaming: false,
  });
  const usedArray = Array.from(usedLabels);

  // ── Attempt 1: standard label generation ──────────────────────────────────
  // 5 docs × 500 chars — significantly more signal than the original 3 × 300.
  const sampleText = sampleDocs
    .slice(0, 5)
    .map((d, i) => `[Sample ${i + 1}]\n${d.pageContent.slice(0, 500)}`)
    .join("\n---\n");

  const LabelSchema = z.object({
    mechanistic_vulnerability_identifier: z // Change from 'label'
      .string()
      .min(10)
      .describe(
        `A unique, highly specific snake_case identifier. ` +
          `Example: 'math_rounding_error' instead of 'high'. ` +
          `MUST NOT BE: [${usedArray.join(", ")}]`,
      ),
    primary_exploit_vector: z
      .string()
      .describe("The step-by-step logic of the exploit."), // Extra field for context
    rationale: z.string().max(500),
  });

  // ADD THIS LINE TO FIX THE ERROR:
  (LabelSchema as any)._example = {
    mechanistic_vulnerability_identifier: "reentrancy_via_token_callback",
    primary_exploit_vector:
      "User calls the contract, contract violates CEI pattern, leading to reentrancy",
    rationale:
      "Findings involving external calls to untrusted tokens before state updates.",
  };

  const systemPrompt =
    `You are a Senior Smart Contract Auditor. ` +
    `CRITICAL RULE: You are building a taxonomy. You MUST NOT reuse any of these identifiers: [${usedArray.join(", ")}]. ` +
    `If a cluster looks like 'high severity', you must identify the SPECIFIC reason (e.g., 'reward_debt_dilution') rather than the severity level.`;

  const userPromptBase = `
        [GOOD EXAMPLES]
        - price_oracle_manipulation
        - math_error
        - cross_contract_reentrancy
        - access_control
        - governance_attack

        [BAD EXAMPLES]
        - high
        - dos
        - logic_error

        Samples from cluster ${clusterId}:
        ${sampleText}
        ...
    `;

  const attempt1 = await invokeWithSchema({
    model,
    systemPrompt,
    userPrompt: userPromptBase,
    schema: LabelSchema,
    stage: `cluster-label-${clusterId}-attempt1`,
    maxRetries: 1,
  });

  //   console.log(
  //     `
  //     Attempt - 1 Log RAW
  //     `,
  //     attempt1,
  //   );

  if (
    attempt1.ok &&
    !usedLabels.has(attempt1.data.mechanistic_vulnerability_identifier)
  ) {
    // console.log(
    //   `
    // Attempt - 1
    // `,
    //   attempt1.data,
    // );

    return attempt1.data.mechanistic_vulnerability_identifier;
  }

  // ── Attempt 2: explicit differentiation prompt ────────────────────────────
  // The LLM returned a duplicate. Give it fresh samples (different slice)
  // and explicitly ask it to find the mechanistic distinction.
  const conflictLabel = attempt1.ok
    ? attempt1.data.mechanistic_vulnerability_identifier
    : "(failed)";

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

  if (
    attempt2.ok &&
    !usedLabels.has(attempt2.data.mechanistic_vulnerability_identifier)
  ) {
    return attempt2.data.mechanistic_vulnerability_identifier;
  }

  // ── Forced suffix fallback ────────────────────────────────────────────────
  // Both LLM attempts produced a duplicate. Extract the most distinguishing
  // keyword from the sample text and append as a sub-class qualifier.
  // Guarantees uniqueness without another API call.
  const baseLabel = attempt2.ok
    ? attempt2.data.mechanistic_vulnerability_identifier
    : attempt1.ok
      ? attempt1.data.mechanistic_vulnerability_identifier
      : (sampleDocs[0]?.metadata?.category ?? `cluster`);

  // Strip any trailing numeric suffix from a previously-suffixed fallback
  const cleanBase = baseLabel.replace(/_\d+$/, "");

  const distinguishingKeywords = [
    "callback",
    "hook",
    "flash_loan",
    "delegatecall",
    "proxy",
    "permit",
    "signature",
    "deadline",
    "slippage",
    "rounding",
    "truncation",
    "overflow",
    "underflow",
    "sandwich",
    "frontrun",
    "backrun",
    "mev",
    "governance",
    "timelock",
    "multisig",
    "pausable",
    "upgrade",
    "initializer",
    "storage",
    "slot",
    "collision",
    "shadowing",
    "assembly",
    "selfdestruct",
    "create2",
    "cross_chain",
    "bridge",
    "relayer",
    "sequencer",
    "l2",
    "rollup",
    "erc20",
    "erc721",
    "erc1155",
    "erc4626",
    "erc777",
    "erc2612",
    "twap",
    "chainlink",
    "pyth",
    "uniswap",
    "balancer",
    "curve",
    "aave",
    "compound",
    "yield",
    "vault",
    "pool",
    "pair",
    "router",
    "factory",
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

  const fallbackLabel = (
    distinguisher
      ? `${cleanBase}_${distinguisher}`
      : `${cleanBase}_${clusterId}`
  ).replaceAll("-", "_");

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
