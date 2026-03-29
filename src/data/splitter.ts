import { Document } from "@langchain/core/documents";
import { RecursiveCharacterTextSplitter } from "@langchain/textsplitters";

/**
 * Solodit findings are structured text, not prose.
 * Smaller chunks → more precise vector search results.
 */
const CHUNK_SIZE = 800;
const CHUNK_OVERLAP = 200;

const splitter = new RecursiveCharacterTextSplitter({
  chunkSize: CHUNK_SIZE,
  chunkOverlap: CHUNK_OVERLAP,
});

/** Split an array of LangChain Documents into smaller chunks for embedding. */
export async function splitDocuments(docs: Document[]): Promise<Document[]> {
  if (!docs.length) return [];

  const chunks = await splitter.splitDocuments(docs);
  return chunks.map((chunk, idx) => ({
    pageContent: chunk.pageContent,
    metadata: {
      ...chunk.metadata,
      _chunkIndex: idx,
    },
  }));
}

// ─── Solodit Finding Shape ────────────────────────────────────────────────────

export interface RawFinding {
  id: string;
  title: string;
  description: string;
  severity: string;
  protocol: string;
  category: string;
  url?: string;
}

/**
 * Convert a raw finding into a LangChain Document.
 *
 * Layout: title + severity + category first (high signal for similarity search),
 * then description (detail). First chunk is always most informative.
 */
export function findingToDocument(f: RawFinding): Document {
  const content = [
    `Title: ${f.title}`,
    `Severity: ${f.severity}`,
    `Category: ${f.category}`,
    `Protocol: ${f.protocol}`,
    ``,
    f.description.trim(),
  ].join("\n");

  return new Document({
    pageContent: content,
    metadata: {
      source: f.url ?? `solodit:${f.id}`,
      findingId: f.id,
      severity: f.severity,
      protocol: f.protocol,
      category: f.category,
      // clusterId gets added by 02_cluster.ts when it rebuilds the index
      clusterId: -1,
    },
  });
}

// ─── Markdown Audit Report Parser ────────────────────────────────────────────

/**
 * Severity code → normalized severity label.
 * Covers the prefixes used across all audit firms in solodit_content.
 */
const SEVERITY_MAP: Record<string, string> = {
  C: "Critical",
  CR: "Critical",
  CRIT: "Critical",
  H: "High",
  HI: "High",
  HIGH: "High",
  M: "Medium",
  MED: "Medium",
  MEDIUM: "Medium",
  L: "Low",
  LO: "Low",
  LOW: "Low",
  I: "Info",
  IN: "Info",
  INFO: "Info",
  N: "Info", // "Note" used by some firms
  G: "Info", // "Gas" — included but low value for audit RAG
  Q: "Info", // "Quality" / "QA"
};

/**
 * Patterns that identify the start of a finding section in a markdown report.
 *
 * Handles the formats used across solodit_content firms:
 *   ## [H-01] Title
 *   ## [H-01]: Title
 *   ## H-01: Title
 *   ## **[H-01]** Title
 *   ### [MEDIUM] Title
 *   ## Issue 1: Title
 *   ## Finding 1 (High): Title
 *
 * Capture group 1: the severity code/identifier
 * Capture group 2 (optional): the title text after the identifier
 */
const FINDING_HEADER_RE =
  /^#{1,4}\s+(?:\*{1,2})?\[?([A-Z]{1,4}[-–]?\d{1,3}|HIGH|MEDIUM|LOW|CRITICAL|INFORMATIONAL|INFO|GAS|QA|NOTE)\]?(?:\*{1,2})?[:\s\-–]+(.+)?$/im;

/**
 * Extract severity label from a finding identifier string.
 * e.g. "H-01" → "High", "MEDIUM" → "Medium", "C-02" → "Critical"
 */
function extractSeverity(id: string): string {
  // Full word match first (e.g. "HIGH", "MEDIUM")
  const upper = id.toUpperCase().replace(/[-\s\d]/g, "");
  if (SEVERITY_MAP[upper]) return SEVERITY_MAP[upper];

  // Leading letter prefix (e.g. "H" from "H-01", "CR" from "CR-03")
  const prefix = id.replace(/[-\d\s]/g, "").toUpperCase();
  return SEVERITY_MAP[prefix] ?? SEVERITY_MAP[prefix.slice(0, 1)] ?? "Info";
}

/**
 * Extract a clean protocol name from an audit report filename.
 * e.g. "2023-07-26-Buffer-v2.5.md" → "Buffer"
 *      "2024-09-22-stUSDCxBloom.md" → "stUSDCxBloom"
 *      "Ubet-Parlay-Security-Audit.md" → "Ubet-Parlay"
 */
function extractProtocolFromFilename(filename: string): string {
  // Remove date prefix (YYYY-MM-DD-)
  const withoutDate = filename.replace(/^\d{4}-\d{2}-\d{2}-?/, "");
  // Remove .md extension
  const withoutExt = withoutDate.replace(/\.md$/i, "");
  // Remove common suffixes
  const withoutSuffix = withoutExt
    .replace(/-?(security[- ]?)?audit[-_ v\d.]*$/i, "")
    .replace(/-?report[-_ v\d.]*$/i, "")
    .replace(/-?review[-_ v\d.]*$/i, "");
  return withoutSuffix || withoutExt || filename;
}

/**
 * Parse a full markdown audit report into individual findings.
 *
 * Strategy:
 * 1. Split the document into lines.
 * 2. Scan for heading lines that match the finding header pattern.
 * 3. Collect all lines between two finding headers as the finding's content.
 * 4. Build a RawFinding for each section.
 *
 * Reports with no recognizable findings return an empty array (e.g. pure
 * scoping docs, executive summary files). The ingest script skips these.
 *
 * @param content  Full markdown text of the audit report.
 * @param filename The `.md` filename (used for protocol extraction).
 * @param firmName The audit firm / platform name (parent folder name).
 * @param relPath  Relative path used as the source URL in metadata.
 */
export function parseMarkdownReport(
  content: string,
  filename: string,
  firmName: string,
  relPath: string,
): RawFinding[] {
  const lines = content.split("\n");
  const protocol = extractProtocolFromFilename(filename);
  const findings: RawFinding[] = [];

  // Track where each finding section starts
  interface FindingStart {
    lineIndex: number;
    id: string;
    severity: string;
    titleFromHeader: string;
  }

  const starts: FindingStart[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    const match = line.match(FINDING_HEADER_RE);
    if (!match) continue;

    const rawId = match[1] ?? "";
    const titleFromHeader = (match[2] ?? "").trim();
    const severity = extractSeverity(rawId);

    // Skip pure gas/QA findings — they add noise without security signal
    if (
      rawId.toUpperCase().startsWith("G") ||
      rawId.toUpperCase().startsWith("Q")
    )
      continue;

    starts.push({ lineIndex: i, id: rawId, severity, titleFromHeader });
  }

  // Collect content between consecutive starts
  for (let s = 0; s < starts.length; s++) {
    const start = starts[s];
    const endLine =
      s + 1 < starts.length ? starts[s + 1].lineIndex : lines.length;

    // The section content (everything after the header line)
    const sectionLines = lines.slice(start.lineIndex + 1, endLine);
    const sectionText = sectionLines.join("\n").trim();

    if (!sectionText) continue; // Empty section, skip

    // Try to extract a better title from the section body if header title is thin
    let title = start.titleFromHeader;
    if (!title || title.length < 5) {
      // Look for the first non-empty line or a bold title pattern in the body
      const firstContentLine = sectionLines
        .map(l => l.trim())
        .find(
          l =>
            l.length > 5 &&
            !l.startsWith("#") &&
            !l.startsWith("|") &&
            !l.startsWith("---"),
        );
      if (firstContentLine) {
        // Strip markdown bold/italic formatting
        title = firstContentLine.replace(/\*{1,2}([^*]+)\*{1,2}/g, "$1").trim();
        // Cap at 100 chars
        if (title.length > 100) title = title.slice(0, 97) + "...";
      }
    }

    // Infer category from severity and content keywords
    const category = inferCategory(sectionText, start.severity);

    const finding: RawFinding = {
      id: `${firmName}__${filename}__${start.id}`,
      title: title || `${start.severity} finding in ${protocol}`,
      description: sectionText,
      severity: start.severity,
      protocol,
      category,
      url: `solodit:${relPath}#${start.id}`,
    };

    findings.push(finding);
  }

  return findings;
}

/**
 * Infer a vulnerability category from the finding's text content.
 * Used to populate the `category` metadata field for retrieval filtering.
 *
 * This is a lightweight heuristic — the k-means clustering will organize
 * findings more accurately. This is just a first-pass label for bookkeeping.
 */
function inferCategory(text: string, severity: string): string {
  const lower = text.toLowerCase();

  if (/reentrancy|re-entrancy/.test(lower)) return "reentrancy";
  if (/price\s+manipulat|oracle|twap|chainlink|spot\s+price/.test(lower))
    return "oracle-manipulation";
  if (/flash\s*loan/.test(lower)) return "flash-loan";
  if (/access\s*control|onlyowner|onlyadmin|unauthorized|privilege/.test(lower))
    return "access-control";
  if (/overflow|underflow|arithmetic|unchecked\s+math/.test(lower))
    return "arithmetic";
  if (/front.?run|sandwich|mev/.test(lower)) return "frontrunning";
  if (/denial.of.service|dos\b|gas\s+limit|unbounded\s+loop/.test(lower))
    return "dos";
  if (/integer\s+overflow|integer\s+underflow/.test(lower)) return "arithmetic";
  if (/signature|replay|ecrecover/.test(lower)) return "signature";
  if (/governance|voting|proposal|timelock/.test(lower)) return "governance";
  if (/liquidat/.test(lower)) return "liquidation";
  if (/upgrade|proxy|delegate.?call|implementation/.test(lower))
    return "proxy-upgrade";
  if (/centrali[sz]ation|admin\s+key|single\s+point/.test(lower))
    return "centralization";
  if (/rounding|precision|truncat/.test(lower)) return "rounding";
  if (/erc.?4626|vault\s+share/.test(lower)) return "erc4626";
  if (/erc.?20|token\s+transfer|safeTransfer/.test(lower)) return "erc20";
  if (/erc.?721|nft|non.fungible/.test(lower)) return "erc721";
  if (/cross.chain|bridge|ccip|layerzero/.test(lower)) return "cross-chain";
  if (/storage\s+collision|slot\s+collision/.test(lower))
    return "storage-collision";

  // Fallback: use severity as category
  return severity.toLowerCase();
}
