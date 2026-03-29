import { Document } from "@langchain/core/documents";
import { RecursiveCharacterTextSplitter } from "@langchain/textsplitters";

/**
 * Solodit findings are structured text, not prose.
 * Smaller chunks → more precise vector search results.
 */
const CHUNK_SIZE = 500;
const CHUNK_OVERLAP = 80;

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
 * Convert a raw Solodit finding into a LangChain Document.
 *
 * The pageContent layout is designed for semantic similarity search:
 * title + severity + category first (high signal), then description (detail).
 * This ordering matters for chunking — first chunk is always the most informative.
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
      // clusterId gets added by 03_cluster.ts when it rebuilds the index
      clusterId: -1,
    },
  });
}
