import { readFile, writeFile, unlink } from "fs/promises";
import { existsSync, mkdirSync } from "fs";
import { join } from "path";
import { env } from "../utils/env.js";
import { logger } from "../utils/logger.js";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface IngestCheckpoint {
  /** Bump this when the checkpoint schema changes. */
  version: 1;
  startedAt: string;
  /** Provider + model that was used to embed. Mismatch = error. */
  embeddingProvider: string;
  embeddingModel: string;
  /** Categories where every finding has been embedded and saved to disk. */
  completedCategories: string[];
  /** Category currently being processed. null = between categories. */
  inProgressCategory: string | null;
  /** Index within inProgressCategory's raw JSON array to resume from. */
  inProgressOffset: number;
  /** Running total of embeddings successfully written to disk. */
  totalIngested: number;
  /** True after scripts/03_cluster.ts has run successfully. */
  clustered: boolean;
}

// ─── File Path ────────────────────────────────────────────────────────────────

function checkpointPath(): string {
  return join(env.DATA_DIR, "ingest-checkpoint.json");
}

// ─── Public API ───────────────────────────────────────────────────────────────

export async function readCheckpoint(): Promise<IngestCheckpoint | null> {
  const path = checkpointPath();
  if (!existsSync(path)) return null;

  try {
    const raw = await readFile(path, "utf-8");
    return JSON.parse(raw) as IngestCheckpoint;
  } catch (err) {
    logger.warn("checkpoint", `Could not read checkpoint, starting fresh`, {
      error: (err as Error).message,
    });
    return null;
  }
}

export async function writeCheckpoint(cp: IngestCheckpoint): Promise<void> {
  const dir = env.DATA_DIR;
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  await writeFile(checkpointPath(), JSON.stringify(cp, null, 2), "utf-8");
  logger.debug("checkpoint", "Saved", {
    total: cp.totalIngested,
    completed: cp.completedCategories.length,
    inProgress: cp.inProgressCategory,
    offset: cp.inProgressOffset,
  });
}

export async function clearCheckpoint(): Promise<void> {
  const path = checkpointPath();
  if (existsSync(path)) {
    await unlink(path);
    logger.info("checkpoint", "Cleared — next ingest will start from scratch");
  }
}

export function createFreshCheckpoint(
  embeddingProvider: string,
  embeddingModel: string,
): IngestCheckpoint {
  return {
    version: 1,
    startedAt: new Date().toISOString(),
    embeddingProvider,
    embeddingModel,
    completedCategories: [],
    inProgressCategory: null,
    inProgressOffset: 0,
    totalIngested: 0,
    clustered: false,
  };
}

/**
 * Throws a clear error if the embedding model changed since last run.
 * Mixing embeddings from different models in the same HNSWLib index is
 * silent corruption — distances become meaningless.
 */
export function validateCheckpointCompatibility(
  cp: IngestCheckpoint,
  currentProvider: string,
  currentModel: string,
): void {
  if (
    cp.embeddingProvider !== currentProvider ||
    cp.embeddingModel !== currentModel
  ) {
    throw new Error(
      `\n❌  Embedding model mismatch — cannot resume.\n\n` +
        `  Checkpoint built with: ${cp.embeddingProvider}/${cp.embeddingModel}\n` +
        `  Current config:        ${currentProvider}/${currentModel}\n\n` +
        `  Mixing different embedding models corrupts the vector index.\n` +
        `  To rebuild with the new model:\n` +
        `    npm run ingest -- --fresh\n`,
    );
  }
}
