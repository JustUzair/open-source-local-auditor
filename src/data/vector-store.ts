import { HNSWLib } from "@langchain/community/vectorstores/hnswlib";
import { existsSync, mkdirSync } from "fs";
import { join } from "path";
import { makeEmbeddingsModel } from "../utils/models.js";
import { env } from "../utils/env.js";
import { logger } from "../utils/logger.js";

export function storePath(): string {
  return join(env.DATA_DIR, "vectorstore");
}

// Singleton — loaded once per process for the audit pipeline.
let _runtimeStore: HNSWLib | null = null;

// ─── Runtime (audit pipeline) ─────────────────────────────────────────────────

/**
 * Load the pre-built vector store. Used by the audit pipeline.
 * Throws with a clear setup guide if the index hasn't been built yet.
 */
export async function getVectorStore(): Promise<HNSWLib> {
  if (_runtimeStore) return _runtimeStore;

  const dir = storePath();
  const indexFile = join(dir, "hnswlib.index");

  if (!existsSync(indexFile)) {
    throw new Error(
      `\n❌  Vector store not found at ${dir}\n\n` +
        `Run one of:\n` +
        `  npm run setup              — full setup (scrape + ingest + cluster)\n` +
        `  npm run setup -- --download  — download pre-built index from releases\n` +
        `  npm run ingest             — build index from existing raw data in data/raw/\n`,
    );
  }

  logger.info("vector-store", `Loading index from ${dir}`);
  _runtimeStore = await HNSWLib.load(dir, makeEmbeddingsModel());
  return _runtimeStore;
}

/** Clear singleton (used in tests and after ingest rebuilds the index). */
export function resetVectorStoreCache(): void {
  _runtimeStore = null;
}

// ─── Ingest / Build (scripts only) ───────────────────────────────────────────

/**
 * Load existing store from disk for resuming an interrupted ingest.
 * Returns null if no store exists (fresh start — build from first batch).
 */
export async function loadStoreForResume(): Promise<HNSWLib | null> {
  const dir = storePath();
  const indexFile = join(dir, "hnswlib.index");
  if (!existsSync(indexFile)) return null;

  logger.info("vector-store", "Loading existing store to resume ingest");
  return HNSWLib.load(dir, makeEmbeddingsModel());
}

/**
 * Save the store to disk. Called after every batch during ingest
 * so a crash loses at most one batch worth of work.
 */
export async function saveStore(store: HNSWLib): Promise<void> {
  const dir = storePath();
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  await store.save(dir);
  logger.debug("vector-store", `Saved to ${dir}`);
}

/**
 * Create a brand-new store from an initial batch of documents + their vectors.
 * Only called once per fresh ingest (the very first batch).
 */
export async function createStore(
  vectors: number[][],
  documents: import("@langchain/core/documents").Document[],
): Promise<HNSWLib> {
  const dir = storePath();
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });

  const embeddings = makeEmbeddingsModel();
  const store = await HNSWLib.fromDocuments(documents, embeddings);

  // HNSWLib.fromDocuments re-embeds internally. For large batches we use
  // addVectors directly (see 02_ingest.ts) to avoid double-embedding.
  // This factory is only used for the very first batch where we need to
  // initialize the index.
  await store.save(dir);
  return store;
}
