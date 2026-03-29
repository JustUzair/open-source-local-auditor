import { existsSync } from "fs";
import { copyFile, readFile, writeFile } from "fs/promises";
import { join } from "path";
import { execSync, spawnSync } from "child_process";
import dotenv from "dotenv";

dotenv.config();

const DATA_DIR = process.env.DATA_DIR ?? "./data";
const args = process.argv.slice(2);
const DOWNLOAD_MODE = args.includes("--download");
const FRESH_MODE = args.includes("--fresh");

/**
 * GitHub Releases URL for the pre-built vector store.
 * Update this when a new release with pre-built data is published.
 * Set to empty string until the first release is published.
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

function run(script: string, extraArgs: string[] = []): boolean {
  const result = spawnSync("npx", ["tsx", script, ...extraArgs], {
    stdio: "inherit",
    shell: false,
  });
  return result.status === 0;
}

// ─── Checks ───────────────────────────────────────────────────────────────────

async function checkEnv(): Promise<void> {
  step("🔧", "Checking environment configuration");

  if (!existsSync(".env")) {
    if (existsSync(".env.example")) {
      await copyFile(".env.example", ".env");
      console.log("\n   📄  .env created from .env.example");
      console.log(
        "   ⚠️   Please set your API keys in .env, then re-run setup.\n",
      );
      process.exit(0);
    } else {
      console.error(
        "   ❌  .env.example not found. Is this the right directory?\n",
      );
      process.exit(1);
    }
  }

  ok(".env found");

  // Validate env by importing (triggers Zod validation)
  try {
    const { env } = await import("../utils/env.js");
    void env.NODE_ENV; // trigger validation
    ok(`Auditor 1: ${env.AUDITOR_1_PROVIDER}/${env.AUDITOR_1_MODEL}`);
    ok(`Supervisor: ${env.SUPERVISOR_PROVIDER}/${env.SUPERVISOR_MODEL}`);
    ok(`Embeddings: ${env.EMBEDDING_PROVIDER}/${env.EMBEDDING_MODEL}`);
  } catch (err) {
    console.error("\n", (err as Error).message);
    process.exit(1);
  }
}

async function checkVectorStore(): Promise<boolean> {
  const indexPath = join(DATA_DIR, "vectorstore", "hnswlib.index");
  return existsSync(indexPath);
}

async function downloadPrebuiltIndex(): Promise<void> {
  step("⬇️ ", "Downloading pre-built vector index");

  if (!PREBUILT_INDEX_URL) {
    console.error(
      "   ❌  No pre-built index URL configured.\n" +
        "   Set PREBUILT_INDEX_URL in .env, or run without --download to build locally.\n",
    );
    process.exit(1);
  }

  // Use curl or wget to download the tar.gz and extract it
  const outPath = join(DATA_DIR, "vectorstore.tar.gz");
  info(`Downloading from: ${PREBUILT_INDEX_URL}`);

  const curl = spawnSync("curl", ["-L", "-o", outPath, PREBUILT_INDEX_URL], {
    stdio: "inherit",
  });

  if (curl.status !== 0) {
    console.error(
      "   ❌  Download failed. Check the URL and your internet connection.\n",
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

  // Step 1: Environment
  await checkEnv();

  // Step 2: Vector store
  step("📦", "Checking vector store");

  const storeExists = await checkVectorStore();

  if (storeExists && !FRESH_MODE) {
    skip("Pre-built index found. Skipping ingest.");
    info("To rebuild: npm run setup -- --fresh");
  } else if (DOWNLOAD_MODE) {
    await downloadPrebuiltIndex();
  } else {
    // Build from scratch
    step("🕷️ ", "Scraping Solodit vulnerability database");
    const rawDir = join(DATA_DIR, "raw");
    if (existsSync(rawDir) && !FRESH_MODE) {
      skip("Raw data already scraped. Skipping.");
      info("To re-scrape: delete data/raw/ and re-run");
    } else {
      const scraped = run("src/scripts/01_scrape.ts");
      if (!scraped) {
        console.error(
          "   ❌  Scraping failed. Check your network connection.\n",
        );
        process.exit(1);
      }
    }

    step("📥", "Ingesting findings into vector store");
    const extraArgs = FRESH_MODE ? ["--fresh"] : [];
    const ingested = run("src/scripts/02_ingest.ts", extraArgs);
    if (!ingested) {
      console.error(
        "   ❌  Ingest failed.\n" +
          "   If it was a rate limit, run: npm run ingest (it will resume)\n",
      );
      process.exit(1);
    }

    step("🔵", "Running k-means clustering");
    const clustered = run("src/scripts/03_cluster.ts");
    if (!clustered) {
      console.error(
        "   ❌  Clustering failed.\n" +
          "   You can still use the tool — run: npm run cluster to retry\n",
      );
      // Non-fatal — tool works with plain similarity search as fallback
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
