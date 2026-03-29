/**
 * 00_setup.ts — SentinelAI Setup Orchestrator
 *
 * Single command that gets everything ready:
 *   1. Check .env exists and is valid
 *   2. Check solodit_content submodule is hydrated
 *   3. Check / build the vector store:
 *        --download  → fetch pre-built index from GitHub Releases
 *        (default)   → run ingest + cluster from submodule data
 *
 * Usage:
 *   npm run setup                  — full setup
 *   npm run setup -- --download    — download pre-built index
 *   npm run setup -- --fresh       — force rebuild even if index exists
 */

import { existsSync } from "fs";
import { copyFile } from "fs/promises";
import { join } from "path";
import { spawnSync } from "child_process";
import dotenv from "dotenv";

dotenv.config();

const DATA_DIR = process.env.DATA_DIR ?? "./data";
const args = process.argv.slice(2);
const DOWNLOAD_MODE = args.includes("--download");
const FRESH_MODE = args.includes("--fresh");

/**
 * GitHub Releases URL for the pre-built vector store archive.
 * Set this in .env as PREBUILT_INDEX_URL once a release is published.
 * Leave empty to always build locally.
 */
const PREBUILT_INDEX_URL = process.env.PREBUILT_INDEX_URL ?? "";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function step(emoji: string, message: string): void {
  console.log(`\n${emoji}  ${message}`);
}
function ok(message: string): void {
  console.log(`   ✅  ${message}`);
}
function skip(message: string): void {
  console.log(`   ⏭️   ${message}`);
}
function info(message: string): void {
  console.log(`   ℹ️   ${message}`);
}
function warn(message: string): void {
  console.log(`   ⚠️   ${message}`);
}

function run(script: string, extraArgs: string[] = []): boolean {
  const result = spawnSync("npx", ["tsx", script, ...extraArgs], {
    stdio: "inherit",
    shell: false,
  });
  return result.status === 0;
}

// ─── Step 1: Environment Check ────────────────────────────────────────────────

async function checkEnv(): Promise<void> {
  step("🔧", "Checking environment configuration");

  if (!existsSync(".env")) {
    if (existsSync(".env.example")) {
      await copyFile(".env.example", ".env");
      console.log("\n   📄  .env created from .env.example");
      console.log(
        "   ⚠️   Please review .env and set any required API keys, then re-run setup.\n",
      );
      process.exit(0);
    } else {
      console.error(
        "   ❌  .env.example not found. Are you in the project root?\n",
      );
      process.exit(1);
    }
  }

  ok(".env found");

  // Trigger Zod validation
  try {
    const { env } = await import("../utils/env.js");
    void env.NODE_ENV;
    ok(`Auditor 1: ${env.AUDITOR_1_PROVIDER}/${env.AUDITOR_1_MODEL}`);
    ok(`Auditor 2: ${env.AUDITOR_2_PROVIDER}/${env.AUDITOR_2_MODEL}`);
    ok(`Auditor : ${env.AUDITOR_3_PROVIDER}/${env.AUDITOR_3_MODEL}`);
    ok(`Supervisor: ${env.SUPERVISOR_PROVIDER}/${env.SUPERVISOR_MODEL}`);
    ok(`Embeddings: ${env.EMBEDDING_PROVIDER}/${env.EMBEDDING_MODEL}`);

    // Warn if using ollama embeddings but Ollama isn't running
    if (env.EMBEDDING_PROVIDER === "ollama") {
      const ping = spawnSync("curl", [
        "-sf",
        `${env.OLLAMA_BASE_URL}/api/tags`,
      ]);
      if (ping.status !== 0) {
        warn(`Ollama doesn't appear to be running at ${env.OLLAMA_BASE_URL}`);
        warn(`Start it with: ollama serve`);
        warn(
          `Then pull the embedding model: ollama pull ${env.EMBEDDING_MODEL}`,
        );
      } else {
        ok(`Ollama reachable at ${env.OLLAMA_BASE_URL}`);
      }
    }
  } catch (err) {
    console.error("\n", (err as Error).message);
    process.exit(1);
  }
}

// ─── Step 2: Submodule Check ──────────────────────────────────────────────────

async function checkSubmodule(): Promise<void> {
  step("📚", "Checking solodit_content submodule");

  const reportsDir = join(DATA_DIR, "solodit_content", "reports");

  if (existsSync(reportsDir)) {
    // Count firm folders as a quick sanity check
    const { readdirSync } = await import("fs");
    try {
      const firms = readdirSync(reportsDir);
      ok(`solodit_content hydrated — ${firms.length} audit firm folders found`);
      return;
    } catch {
      // Fall through to hydrate
    }
  }

  // Not hydrated — run npm run hydrate
  info("solodit_content not found. Hydrating submodule...");
  const result = spawnSync("npm", ["run", "hydrate"], { stdio: "inherit" });

  if (result.status !== 0) {
    console.error(
      "\n   ❌  Submodule hydration failed.\n" +
        "   Try manually: git submodule update --init --recursive\n",
    );
    process.exit(1);
  }

  ok("solodit_content submodule hydrated");
}

// ─── Step 3: Vector Store ─────────────────────────────────────────────────────

async function checkVectorStore(): Promise<boolean> {
  const indexPath = join(DATA_DIR, "vectorstore", "hnswlib.index");
  return existsSync(indexPath);
}

async function downloadPrebuiltIndex(): Promise<void> {
  step("⬇️ ", "Downloading pre-built vector index");

  if (!PREBUILT_INDEX_URL) {
    console.error(
      "   ❌  PREBUILT_INDEX_URL not set in .env.\n" +
        "   Run without --download to build locally from the submodule.\n",
    );
    process.exit(1);
  }

  const outPath = join(DATA_DIR, "vectorstore.tar.gz");
  info(`URL: ${PREBUILT_INDEX_URL}`);

  const curl = spawnSync("curl", ["-L", "-o", outPath, PREBUILT_INDEX_URL], {
    stdio: "inherit",
  });

  if (curl.status !== 0) {
    console.error(
      "   ❌  Download failed. Check the URL and your connection.\n",
    );
    process.exit(1);
  }

  info("Extracting...");
  spawnSync("tar", ["-xzf", outPath, "-C", DATA_DIR], { stdio: "inherit" });
  ok("Pre-built index ready");
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  console.log("\n🛡️   SentinelAI — Setup\n");
  console.log("══════════════════════════════════════════");

  // 1. Environment
  await checkEnv();

  // 2. Submodule (always check — data source for ingest)
  await checkSubmodule();

  // 3. Vector store
  step("📦", "Checking vector store");
  const storeExists = await checkVectorStore();

  if (storeExists && !FRESH_MODE) {
    skip("Vector index found. Skipping ingest.");
    info("To rebuild from latest submodule data: npm run setup -- --fresh");
  } else if (DOWNLOAD_MODE) {
    await downloadPrebuiltIndex();
  } else {
    // Build from scratch using submodule data

    step("📥", "Ingesting Solodit audit reports into vector store");
    const extraArgs = FRESH_MODE ? ["--fresh"] : [];
    const ingested = run("src/scripts/01_ingest.ts", extraArgs);
    if (!ingested) {
      console.error(
        "   ❌  Ingest failed.\n" +
          "   To resume: npm run ingest\n" +
          "   To rebuild: npm run ingest -- --fresh\n",
      );
      process.exit(1);
    }

    step("🔵", "Running k-means clustering");
    const clustered = run("src/scripts/02_cluster.ts");
    if (!clustered) {
      console.error(
        "   ❌  Clustering failed.\n" +
          "   The tool still works with plain similarity search.\n" +
          "   Retry: npm run cluster\n",
      );
      // Non-fatal — retriever falls back to plain similarity search
    }
  }

  // Done
  console.log("\n══════════════════════════════════════════");
  console.log("✅  SentinelAI setup complete!\n");
  console.log("Run an audit:");
  console.log("  npm run sentinel -- audit ./path/to/contracts/");
  console.log("  npm run sentinel -- audit ./contracts.zip\n");
  console.log("Start the web interface:");
  console.log("  npm run dev\n");
}

main().catch(err => {
  console.error("\nSetup failed:", err);
  process.exit(1);
});
