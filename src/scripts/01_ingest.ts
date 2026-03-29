/**
 * 01_ingest.ts — Solodit Submodule Ingest Pipeline
 *
 * Reads every .md audit report from data/solodit_content/reports/,
 * parses each file into individual findings using the markdown parser,
 * embeds them with the configured embedding model (default: local
 * qwen3-embedding:4b via Ollama), and saves to HNSWLib on disk.
 *
 * Checkpoint-aware: crashes and interruptions resume from the last
 * saved position. Run with --fresh to start over.
 *
 * Usage:
 *   npm run ingest             — run or resume
 *   npm run ingest -- --fresh  — clear checkpoint and rebuild from scratch
 *
 * Prerequisites:
 *   npm run hydrate            — pull solodit_content submodule first
 *   ollama pull qwen3-embedding:4b  — if using local embeddings
 */

import { readdir, readFile, appendFile } from "fs/promises";
import { existsSync, mkdirSync, unlinkSync } from "fs";
import { join, relative } from "path";
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
  parseMarkdownReport,
  findingToDocument,
  splitDocuments,
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

/**
 * Root of the solodit_content git submodule.
 * Structure: REPORTS_DIR/<FirmName>/<YYYY-MM-DD-Protocol.md>
 */
const REPORTS_DIR = join(DATA_DIR, "solodit_content", "reports");

/**
 * JSONL file where raw embedding vectors are saved for k-means clustering.
 * Each line: { docIndex, embedding, category }
 */
const EMBEDDINGS_FILE = join(DATA_DIR, "embeddings-raw.jsonl");

/**
 * Save to disk every N embedded chunks.
 * Limits data loss on crash or interruption.
 */
const BATCH_SIZE = 50;

/**
 * Delay between Ollama embedding calls (ms).
 * Ollama is local so no rate limiting is needed, but a small delay
 * avoids hammering the process and allows the OS to breathe.
 * Set to 0 if you want maximum speed.
 */
const EMBED_DELAY_MS = 50;

// ─── File Discovery ───────────────────────────────────────────────────────────

interface ReportFile {
  /** Absolute path to the .md file */
  absPath: string;
  /** Relative path from REPORTS_DIR, e.g. "0x52/2023-07-26-Buffer-v2.5.md" */
  relPath: string;
  /** Audit firm / platform folder name, e.g. "0x52" */
  firmName: string;
  /** The .md filename, e.g. "2023-07-26-Buffer-v2.5.md" */
  filename: string;
}

/**
 * Walk REPORTS_DIR and return all .md files across all firm subdirectories.
 * Only descends one level deep: reports/<firm>/<file>.md
 * Skips README.md and any non-.md files.
 */
async function discoverReportFiles(): Promise<ReportFile[]> {
  const files: ReportFile[] = [];

  // List firm-level directories
  let firmDirs: string[];
  try {
    firmDirs = await readdir(REPORTS_DIR);
  } catch {
    throw new Error(
      `\n❌  Reports directory not found: ${REPORTS_DIR}\n\n` +
        `   Run: npm run hydrate\n` +
        `   This pulls the solodit_content git submodule.\n`,
    );
  }

  for (const firm of firmDirs) {
    const firmPath = join(REPORTS_DIR, firm);

    // Skip non-directory entries (e.g. README.md at the root)
    let entries: string[];
    try {
      entries = await readdir(firmPath);
    } catch {
      continue;
    }

    for (const entry of entries) {
      if (!entry.endsWith(".md")) continue;
      if (entry.toLowerCase() === "readme.md") continue;

      const absPath = join(firmPath, entry);
      const relPath = `${firm}/${entry}`;

      files.push({
        absPath,
        relPath,
        firmName: firm,
        filename: entry,
      });
    }
  }

  // Sort for deterministic ordering (important for checkpoint consistency)
  files.sort((a, b) => a.relPath.localeCompare(b.relPath));
  return files;
}

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

/**
 * Flush the current batch to the HNSWLib store and save to disk.
 * Returns the updated store (may have been created on first flush).
 */
async function flushBatch(
  store: HNSWLib | null,
  batchVectors: number[][],
  batchDocs: Document[],
  embeddings: ReturnType<typeof makeEmbeddingsModel>,
): Promise<HNSWLib> {
  if (store === null) {
    // First batch ever — initialize the store from scratch.
    // HNSWLib.fromDocuments will re-embed internally, but this only happens
    // once for the very first batch. All subsequent batches use addVectors.
    const newStore = await HNSWLib.fromDocuments(batchDocs, embeddings);
    await saveStore(newStore);
    return newStore;
  }

  await store.addVectors(batchVectors, batchDocs);
  await saveStore(store);
  return store;
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const fresh = args.includes("--fresh");

  console.log("\n📥  SentinelAI — Ingest Pipeline (Solodit Submodule)\n");

  // ── Checkpoint handling ────────────────────────────────────────────────
  let checkpoint = await readCheckpoint();

  if (fresh && checkpoint) {
    console.log("🔄  --fresh flag: clearing checkpoint and existing index\n");
    checkpoint = null;
    if (existsSync(EMBEDDINGS_FILE)) unlinkSync(EMBEDDINGS_FILE);
    // Note: vector store files are NOT deleted here — they're overwritten
    // when the first batch is flushed. If you want a clean slate run
    // `rm -rf data/vectorstore` before --fresh.
  }

  if (checkpoint) {
    validateCheckpointCompatibility(
      checkpoint,
      env.EMBEDDING_PROVIDER,
      env.EMBEDDING_MODEL,
    );
    console.log(`▶️   Resuming from checkpoint`);
    console.log(`   Completed files: ${checkpoint.completedCategories.length}`);
    console.log(
      `   Total chunks ingested so far: ${checkpoint.totalIngested}\n`,
    );
  } else {
    checkpoint = createFreshCheckpoint(
      env.EMBEDDING_PROVIDER,
      env.EMBEDDING_MODEL,
    );
    console.log(`🆕  Starting fresh ingest\n`);
  }

  const embeddings = makeEmbeddingsModel();

  // ── Discover report files ──────────────────────────────────────────────
  console.log("📂  Scanning solodit_content/reports/...");
  const allFiles = await discoverReportFiles();
  console.log(`   Found ${allFiles.length} audit report files\n`);

  // Filter out already-completed files using checkpoint
  const completedSet = new Set(checkpoint.completedCategories);
  const remaining = allFiles.filter(f => !completedSet.has(f.relPath));

  if (remaining.length === 0) {
    console.log("✅  All files already ingested.");
    console.log(`   Total: ${checkpoint.totalIngested} chunks\n`);
    console.log("Next step: npm run cluster\n");
    return;
  }

  console.log(
    `   ${allFiles.length} total files, ${remaining.length} remaining to ingest\n`,
  );

  // ── Load existing store for resuming ──────────────────────────────────
  let store: HNSWLib | null = await loadStoreForResume();

  // ── Progress bar ──────────────────────────────────────────────────────
  const bar = new cliProgress.SingleBar(
    {
      format:
        "  Ingesting [{bar}] {percentage}% | {ingested} chunks | {value}/{total} files | {file}",
      clearOnComplete: false,
    },
    cliProgress.Presets.shades_classic,
  );
  bar.start(remaining.length, 0, {
    ingested: checkpoint.totalIngested,
    file: "",
  });

  let docIndex = checkpoint.totalIngested;
  let skippedFiles = 0;
  let emptyFiles = 0;

  // ── Process each file ─────────────────────────────────────────────────
  for (const [fileIdx, reportFile] of remaining.entries()) {
    bar.update(fileIdx, {
      ingested: checkpoint.totalIngested,
      file: reportFile.relPath,
    });

    // Mark as in-progress in checkpoint before touching the file
    checkpoint.inProgressCategory = reportFile.relPath;
    checkpoint.inProgressOffset = 0;

    // Read file content
    let content: string;
    try {
      content = await readFile(reportFile.absPath, "utf-8");
    } catch (err) {
      logger.warn("ingest", `Could not read file, skipping`, {
        file: reportFile.relPath,
        error: (err as Error).message,
      });
      skippedFiles++;
      checkpoint.completedCategories.push(reportFile.relPath); // Don't retry
      await writeCheckpoint(checkpoint);
      continue;
    }

    // Parse markdown into individual findings
    const findings = parseMarkdownReport(
      content,
      reportFile.filename,
      reportFile.firmName,
      reportFile.relPath,
    );

    if (findings.length === 0) {
      logger.debug("ingest", `No findings parsed from ${reportFile.relPath}`);
      emptyFiles++;
      checkpoint.completedCategories.push(reportFile.relPath);
      await writeCheckpoint(checkpoint);
      continue;
    }

    // Resume from inProgressOffset if we crashed mid-file
    const startOffset = checkpoint.inProgressOffset;
    const toProcess = findings.slice(startOffset);

    // Accumulate batch
    let batchVectors: number[][] = [];
    let batchDocs: Document[] = [];

    for (let i = 0; i < toProcess.length; i++) {
      const finding = toProcess[i];

      // Convert finding → Document → chunks
      const doc = findingToDocument(finding);
      const chunks = await splitDocuments([doc]);

      for (const chunk of chunks) {
        if (EMBED_DELAY_MS > 0) await sleep(EMBED_DELAY_MS);

        let vector: number[];
        try {
          const vectors = await embeddings.embedDocuments([chunk.pageContent]);
          vector = vectors[0];
        } catch (err) {
          logger.warn(
            "ingest",
            `Embedding failed for chunk in ${reportFile.relPath}`,
            { error: (err as Error).message },
          );
          // For cloud APIs: wait and retry once on failure (rate limits)
          // For Ollama: this usually means the model isn't loaded yet
          await sleep(3_000);
          try {
            const vectors = await embeddings.embedDocuments([
              chunk.pageContent,
            ]);
            vector = vectors[0];
          } catch (retryErr) {
            logger.error("ingest", "Retry also failed, skipping chunk", {
              error: (retryErr as Error).message,
            });
            continue;
          }
        }

        batchVectors.push(vector);
        batchDocs.push(chunk);

        // Save raw vector for k-means clustering
        await appendEmbeddingRecord({
          docIndex,
          embedding: vector,
          category: finding.category,
        });
        docIndex++;
      }

      // Flush to disk every BATCH_SIZE chunks
      if (batchVectors.length >= BATCH_SIZE) {
        store = await flushBatch(store, batchVectors, batchDocs, embeddings);
        checkpoint.totalIngested += batchVectors.length;
        checkpoint.inProgressOffset = startOffset + i + 1;
        await writeCheckpoint(checkpoint);
        batchVectors = [];
        batchDocs = [];

        bar.update(fileIdx, { ingested: checkpoint.totalIngested });
      }
    }

    // Flush remaining chunks for this file
    if (batchVectors.length > 0) {
      store = await flushBatch(store, batchVectors, batchDocs, embeddings);
      checkpoint.totalIngested += batchVectors.length;
    }

    // Mark this file as complete
    checkpoint.completedCategories.push(reportFile.relPath);
    checkpoint.inProgressCategory = null;
    checkpoint.inProgressOffset = 0;
    await writeCheckpoint(checkpoint);

    bar.update(fileIdx + 1, { ingested: checkpoint.totalIngested });
  }

  bar.stop();

  // ── Summary ───────────────────────────────────────────────────────────
  console.log(`\n✅  Ingest complete`);
  console.log(
    `   Files processed: ${remaining.length - skippedFiles - emptyFiles}`,
  );
  if (emptyFiles > 0)
    console.log(`   Files with no parsed findings: ${emptyFiles}`);
  if (skippedFiles > 0)
    console.log(`   Files skipped (read errors): ${skippedFiles}`);
  console.log(`   Total chunks embedded: ${checkpoint.totalIngested}`);
  console.log(`   Raw embeddings saved to: ${EMBEDDINGS_FILE}`);
  console.log(`   Vector index saved to: ${storePath()}\n`);
  console.log(`Next step: npm run cluster\n`);
}

main().catch(err => {
  console.error("\nIngest pipeline failed:", err);
  process.exit(1);
});
