# data/

This directory is not tracked by git (see .gitignore).

After running `npm run setup`, it will contain:

- `raw/` — scraped Solodit JSON files (one per vulnerability category)
- `vectorstore/` — HNSWLib index (hnswlib.index + docstore.json)
- `clusters/` — k-means output (centroids.json)
- `embeddings-raw.jsonl` — raw embedding vectors (used by clustering)
- `ingest-checkpoint.json` — ingest progress tracker

To set up: `npm run setup`
To rebuild: `npm run setup -- --fresh`
To download pre-built index: `npm run setup -- --download`
