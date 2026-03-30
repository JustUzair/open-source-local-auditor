import { readdir, readFile } from "fs/promises";
import { existsSync } from "fs";
import { join, relative } from "path";
import AdmZip from "adm-zip";
import type { SourceFile } from "../types/protocol.js";
import { logger } from "../utils/logger.js";

const SKIP_PATTERNS = [
  /node_modules/,
  /\.git\//,
  /\/test(s)?\//i,
  /\/mock(s)?\//i,
  /\/script(s)?\//i,
  /\/deploy\//i,
  /\/artifacts\//,
  /\/cache\//,
  /\/coverage\//,
  /\/dist\//,
  /\/build\//,
  /\/lib\//,
  /\/out\//,
  /\/abi\//,
  /\/deployment\//,
  /\.(json|md|txt|yaml|yml|toml|lock|env|sh|gitmodules|gitignore)$/i,
  /\.(png|jpg|svg|gif|wasm|DS_Store)$/i,
];

function shouldSkip(filePath: string): boolean {
  return SKIP_PATTERNS.some(p => p.test(filePath.replace(/\\/g, "/")));
}

function detectLanguage(filePath: string): string {
  if (filePath.endsWith(".sol")) return "solidity";
  if (filePath.endsWith(".rs")) return "rust";
  if (filePath.endsWith(".move")) return "move";
  if (filePath.endsWith(".go")) return "go";
  if (filePath.endsWith(".ts") || filePath.endsWith(".js")) return "typescript";
  if (filePath.endsWith(".py")) return "python";
  return "other";
}

function scoreAttackSurface(content: string): number {
  let score = 0;
  const c = content.toLowerCase();

  if (
    /transfer|withdraw|deposit|balance|stake|unstake|claim|fee|reward|pay|send|mint|burn/.test(
      c,
    )
  )
    score += 0.3;
  if (/\.call\b|delegatecall|\.invoke|cpi::|cross.chain|callback|hook/.test(c))
    score += 0.25;
  if (
    /onlyowner|onlyadmin|require.*msg\.sender|authority|role|permission|admin/.test(
      c,
    )
  )
    score += 0.15;
  if (/mapping|storage\b|mut\s+\w|global\s+\w/.test(c)) score += 0.1;
  if (/muldiv|wadmul|raymul|shares?|rate|index|price|oracle|twap/.test(c))
    score += 0.15;
  if (/^interface\s+|\/\/.*SPDX.*interface|pub\s+trait\s+/m.test(content))
    score -= 0.2;
  if (/^library\s+\w+\s*\{/m.test(content) && score < 0.2) score -= 0.1;

  return Math.max(0, Math.min(1, score));
}

function extractImports(content: string): string[] {
  const imports: string[] = [];
  for (const m of content.matchAll(
    /import\s+(?:\{[^}]+\}\s+from\s+)?["']([^"']+)["']/g,
  ))
    imports.push(m[1]);
  for (const m of content.matchAll(/^mod\s+(\w+)\s*;/gm)) imports.push(m[1]);
  for (const m of content.matchAll(/use\s+[\w:]+::(\w+)/g)) imports.push(m[1]);
  for (const m of content.matchAll(/import\s+(?:\w+\s+)?"([^"]+)"/g))
    imports.push(m[1]);
  return [...new Set(imports)];
}

function buildSourceFile(relativePath: string, content: string): SourceFile {
  return {
    path: relativePath.replace(/\\/g, "/"),
    content,
    language: detectLanguage(relativePath),
    size: content.length,
    attackScore: scoreAttackSurface(content),
    imports: extractImports(content),
  };
}

export async function loadFromPath(dirPath: string): Promise<SourceFile[]> {
  const files: SourceFile[] = [];

  async function walk(dir: string) {
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const full = join(dir, entry.name);
      const rel = relative(dirPath, full).replace(/\\/g, "/");
      if (shouldSkip(rel) || shouldSkip(entry.name)) continue;
      if (entry.isDirectory()) {
        await walk(full);
      } else if (entry.isFile()) {
        const content = await readFile(full, "utf-8").catch(() => null);
        if (content !== null) files.push(buildSourceFile(rel, content));
      }
    }
  }

  await walk(dirPath);
  logger.info("loader", `Loaded ${files.length} source files from ${dirPath}`);
  return files;
}

export async function loadFromZip(zipPath: string): Promise<SourceFile[]> {
  const zip = new AdmZip(zipPath);
  const entries = zip.getEntries();
  const files: SourceFile[] = [];

  for (const entry of entries) {
    if (entry.isDirectory) continue;
    const entryName = entry.entryName.replace(/\\/g, "/");
    if (shouldSkip(entryName)) continue;
    try {
      const content = entry.getData().toString("utf-8");
      // Skip binary files — non-printable ratio check
      const nonPrintable = (content.match(/[\x00-\x08\x0e-\x1f\x7f]/g) ?? [])
        .length;
      if (nonPrintable / content.length > 0.05) continue;
      files.push(buildSourceFile(entryName, content));
    } catch {
      /* skip */
    }
  }

  logger.info("loader", `Loaded ${files.length} source files from ${zipPath}`);
  return files;
}

/** Unified entry point — auto-detects zip vs directory. */
export async function loadProtocol(input: string): Promise<SourceFile[]> {
  if (!existsSync(input)) throw new Error(`Input path not found: ${input}`);
  const files = input.toLowerCase().endsWith(".zip")
    ? await loadFromZip(input)
    : await loadFromPath(input);
  // Sorted highest attack score first — drives batch priority downstream
  return files.sort((a, b) => b.attackScore - a.attackScore);
}
