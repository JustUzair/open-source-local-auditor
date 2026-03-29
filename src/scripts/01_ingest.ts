import { readdir, readFile, appendFile, writeFile } from "fs/promises";
import { existsSync, mkdirSync, unlinkSync } from "fs";
import { join } from "path";
import cliProgress from "cli-progress";
import dotenv from "dotenv";
import type { Document } from "@langchain/core/documents";
import {
  readCheckpoint,
  writeCheckpoint,
  createFreshCheckpoint,
  validateCheckpointCompatibility,
} from "../data/checkpoint.js";
import {
  findingToDocument,
  splitDocuments,
  type RawFinding,
} from "../data/splitter.js";
import {
  loadStoreForResume,
  saveStore,
  storePath,
} from "../data/vector-store.js";
import { makeEmbeddingsModel } from "../utils/models.js";
import { HNSWLib } from "@langchain/community/vectorstores/hnswlib";
import { env } from "../utils/env.js";
import { logger } from "../utils/logger.js";

dotenv.config();

// ─── Config ───────────────────────────────────────────────────────────────────

const DATA_DIR = env.DATA_DIR;
const RAW_DIR = join(DATA_DIR, "raw");
const EMBEDDINGS_FILE = join(DATA_DIR, "embeddings-raw.jsonl");

/** Save to disk every N embeddings. Limits data loss on crash. */
const BATCH_SIZE = 50;

/** Delay between embedding API calls to avoid rate limits (ms). */
const EMBED_DELAY_MS = 200;

// ─── Helpers ──────────────────────────────────────────────────────────────────

function sleep(ms: number): Promise<void> {
  return new Promise(r => setTimeout(r, ms));
}

/** Append one embedding record to the JSONL file for later k-means. */
async function appendEmbeddingRecord(record: {
  docIndex: number;
  embedding: number[];
  category: string;
}): Promise<void> {
  await appendFile(EMBEDDINGS_FILE, JSON.stringify(record) + "\n", "utf-8");
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const fresh = args.includes("--fresh");

  console.log("\n📥  SentinelAI — Ingest Pipeline\n");

  if (!existsSync(RAW_DIR)) {
    console.error(`❌  Raw data directory not found: ${RAW_DIR}`);
    console.error(`   Run npm run scrape first.\n`);
    process.exit(1);
  }

  const embeddings = makeEmbeddingsModel();

  // ── Checkpoint handling ──────────────────────────────────────────────────
  let checkpoint = await readCheckpoint();

  if (fresh && checkpoint) {
    console.log("🔄  --fresh flag: clearing checkpoint and existing index\n");
    checkpoint = null;
    if (existsSync(EMBEDDINGS_FILE)) unlinkSync(EMBEDDINGS_FILE);
  }

  if (checkpoint) {
    validateCheckpointCompatibility(
      checkpoint,
      env.EMBEDDING_PROVIDER,
      env.EMBEDDING_MODEL,
    );
    console.log(`▶️   Resuming from checkpoint`);
    console.log(
      `   Completed categories: ${checkpoint.completedCategories.length}`,
    );
    console.log(`   Total ingested so far: ${checkpoint.totalIngested}\n`);
  } else {
    checkpoint = createFreshCheckpoint(
      env.EMBEDDING_PROVIDER,
      env.EMBEDDING_MODEL,
    );
    console.log(`🆕  Starting fresh ingest\n`);
  }

  // ── Load or prepare store ────────────────────────────────────────────────
  let store: HNSWLib | null = await loadStoreForResume();
  // store will be null on fresh start — created from first batch below

  // ── Read categories ──────────────────────────────────────────────────────
  const rawFiles = (await readdir(RAW_DIR)).filter(f => f.endsWith(".json"));
  const remaining = rawFiles.filter(
    f => !checkpoint!.completedCategories.includes(f.replace(".json", "")),
  );

  if (remaining.length === 0) {
    console.log("✅  All categories already ingested.");
    console.log(`   Total: ${checkpoint.totalIngested} chunks\n`);
    console.log("Next step: npm run cluster\n");
    return;
  }

  console.log(
    `📂  ${rawFiles.length} categories found, ${remaining.length} remaining\n`,
  );

  const bar = new cliProgress.SingleBar(
    {
      format:
        "  Ingesting [{bar}] {percentage}% | {ingested} chunks | {category}",
      clearOnComplete: false,
    },
    cliProgress.Presets.shades_classic,
  );
  bar.start(remaining.length, 0, {
    ingested: checkpoint.totalIngested,
    category: "",
  });

  let docIndex = checkpoint.totalIngested;

  for (const [fileIdx, rawFile] of remaining.entries()) {
    const category = rawFile.replace(".json", "");
    bar.update(fileIdx, { category, ingested: checkpoint.totalIngested });

    checkpoint.inProgressCategory = category;

    // Load findings for this category
    const raw = await readFile(join(RAW_DIR, rawFile), "utf-8");
    const findings: RawFinding[] = JSON.parse(raw);

    // Resume from offset within this category if we crashed mid-category
    const startOffset = checkpoint.inProgressOffset;
    const toProcess = findings.slice(startOffset);

    // Process in batches
    let batchVectors: number[][] = [];
    let batchDocs: Document[] = [];

    for (let i = 0; i < toProcess.length; i++) {
      const finding = toProcess[i];

      // Convert finding → Document → chunks
      const doc = findingToDocument(finding);
      const chunks = await splitDocuments([doc]);

      for (const chunk of chunks) {
        await sleep(EMBED_DELAY_MS);

        let vector: number[];
        try {
          const vectors = await embeddings.embedDocuments([chunk.pageContent]);
          vector = vectors[0];
        } catch (err) {
          logger.warn("ingest", `Embedding failed for chunk in ${category}`, {
            error: (err as Error).message,
          });
          // On rate limit, wait longer and retry once
          await sleep(5_000);
          try {
            const vectors = await embeddings.embedDocuments([
              chunk.pageContent,
            ]);
            vector = vectors[0];
          } catch {
            logger.error("ingest", "Retry also failed, skipping chunk");
            continue;
          }
        }

        batchVectors.push(vector);
        batchDocs.push(chunk);

        // Save raw embedding for clustering
        await appendEmbeddingRecord({ docIndex, embedding: vector, category });
        docIndex++;
      }

      // Save batch to disk every BATCH_SIZE embeddings
      if (batchVectors.length >= BATCH_SIZE) {
        if (store === null) {
          // First batch — create the store
          const { HNSWLib } =
            await import("@langchain/community/vectorstores/hnswlib");
          store = await HNSWLib.fromDocuments(batchDocs, embeddings);
          // fromDocuments re-embeds, but we've already computed vectors.
          // For the first batch this double-embed is acceptable.
          // Subsequent batches use addVectors to skip re-embedding.
          await saveStore(store);
        } else {
          await store.addVectors(batchVectors, batchDocs);
          await saveStore(store);
        }

        checkpoint.totalIngested += batchVectors.length;
        checkpoint.inProgressOffset = startOffset + i + 1;
        await writeCheckpoint(checkpoint);

        batchVectors = [];
        batchDocs = [];
      }
    }

    // Flush remaining items in this category
    if (batchVectors.length > 0 && store) {
      await store.addVectors(batchVectors, batchDocs);
      await saveStore(store);
      checkpoint.totalIngested += batchVectors.length;
    }

    // Mark category complete
    checkpoint.completedCategories.push(category);
    checkpoint.inProgressCategory = null;
    checkpoint.inProgressOffset = 0;
    await writeCheckpoint(checkpoint);

    bar.update(fileIdx + 1, { ingested: checkpoint.totalIngested, category });
  }

  bar.stop();

  console.log(`\n✅  Ingest complete`);
  console.log(`   Total chunks embedded: ${checkpoint.totalIngested}`);
  console.log(`   Raw embeddings saved to: ${EMBEDDINGS_FILE}`);
  console.log(`   Vector index saved to: ${storePath()}\n`);
  console.log(`Next step: npm run cluster\n`);
}

main().catch(err => {
  console.error("\nIngest pipeline failed:", err);
  process.exit(1);
});
