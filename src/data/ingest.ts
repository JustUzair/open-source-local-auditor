import type { Document } from "@langchain/core/documents";
import type { HNSWLib } from "@langchain/community/vectorstores/hnswlib";
import { saveStore } from "./vector-store.js";
import { logger } from "../utils/logger.js";

export interface BatchIngestResult {
  ok: boolean;
  added: number;
  error?: string;
}

/**
 * Add a batch of documents (with pre-computed embedding vectors) to the store,
 * then save to disk immediately so a crash loses at most this batch.
 *
 * Uses addVectors instead of addDocuments to avoid re-embedding —
 * the ingest script computes embeddings explicitly so it can also save
 * the raw vectors for k-means clustering.
 */
export async function addBatchToStore(
  store: HNSWLib,
  vectors: number[][],
  documents: Document[],
): Promise<BatchIngestResult> {
  if (vectors.length === 0) return { ok: true, added: 0 };
  if (vectors.length !== documents.length) {
    return {
      ok: false,
      added: 0,
      error: `Vector count (${vectors.length}) !== document count (${documents.length})`,
    };
  }

  try {
    await store.addVectors(vectors, documents);
    await saveStore(store);
    logger.debug("ingest", `Batch added`, { count: vectors.length });
    return { ok: true, added: vectors.length };
  } catch (err) {
    const msg = (err as Error).message;
    logger.error("ingest", `Batch add failed`, { error: msg });
    return { ok: false, added: 0, error: msg };
  }
}
