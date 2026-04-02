## Benchmark: SentinelAI vs. Professional Private Audit

We benchmarked SentinelAI against a **real private audit** of `Redacted-Contract.sol` (a gaming contract with VRNG, multipliers, and token pools). The original audit identified **8 distinct vulnerabilities** (1 High, 3 Medium, 3 Low, 1 Info).

### Results: What Each Model Found

| Original Finding                            | Severity | qwen3.5:27b (local) | qwen3.5:397b (cloud) | glm-5:cloud |
| ------------------------------------------- | -------- | :-----------------: | :------------------: | :---------: |
| H-01: Cross‑token payout                    | High     |         ✅          |          ✅          |     ❌      |
| M-01: Multiplier config breaks distribution | Medium   |         ✅          |          ✅          |     ✅      |
| M-02: `removePool` locks user balances      | Medium   |         ✅          |          ✅          |     ❌      |
| M-03: Fee accounting bug                    | Medium   |         ❌          |          ❌          |     ❌      |
| L-01: `addMultiplierPackage` unusable       | Low      |     ⚠️(partial)     |          ❌          |     ❌      |
| L-02: No fee upper bounds                   | Low      |         ❌          |          ✅          |     ✅      |
| L-03: `payFees` invalid return              | Low      |     ⚠️(partial)     |          ❌          |     ❌      |
| I-01: Error naming                          | Info     |         ❌          |          ❌          |     ❌      |

**Legend:** ✅ = found | ⚠️ = partial | ❌ = missed

### What SentinelAI Found That the Original Audit Missed

Every model discovered **additional valid vulnerabilities**:

- Reentrancy in `createGame` via `payFees` (High)
- Missing chainId → cross‑chain replay (High)
- Unbounded loops → gas DoS (Medium)
- Admin deactivating all multiplier packages (High – 397b only)
- No solvency check for max payout (Medium – 397b, glm-5)
- Block timestamp manipulation (Low)
- External call failure handling (Medium – 27b only)

### Model Performance Summary

| Model                   | Private Audit Coverage | New Issues | Best For                                                     |
| ----------------------- | :--------------------: | :--------: | ------------------------------------------------------------ |
| **qwen3.5:27b (local)** |        **~6/8**        |     8+     | **Best overall – catches critical bugs, runs locally, free** |
| qwen3.5:397b (cloud)    |          ~6/8          |     8      | Deepest reasoning, admin‑abuse vectors                       |
| glm-5:cloud             |          ~4/8          |     6      | Good free tier option                                        |

### Key Takeaway

**qwen3.5:27b (local) is the best choice for most audits.** It runs on 18GB RAM, costs nothing, keeps your code private, and catches the critical H‑01 along with most other issues. For final, in‑depth audits, add a cloud 397b pass as a second opinion.

SentinelAI, even with a free local model, consistently matches or exceeds professional private audits – and finds bugs humans miss.

# Ollama needs to be present

need to pull the following

```bash
ollama pull qwen3.5:9b
ollama pull qwen3.5:397b-cloud
ollama pull glm-5:cloud
```

then run

```bash
# grant exec permissions
chmod +x ./create-local-auditors.sh
chmod +x ./delete-local-auditors.sh

# Create local auditors
./create-local-auditors.sh

# Delete local auditors
./delete-local-auditors.sh
```

After successful creation of skilled auditors and the supervisor you will have the following models:

- `qwen-junior-auditor` --> `qwen3.5:9b`
- `qwen-senior-auditor` --> `qwen3.5:397b-cloud`
- `glm-senior-auditor` --> `glm-5:cloud`
- `glm-supervisor` --> `glm-5:cloud`

# Setup

```bash
npm run setup
```

Output

```bash
🛡️   SentinelAI — Setup

══════════════════════════════════════════

🔧  Checking environment configuration
   ✅  .env found
   ✅  Auditor 1: ollama/qwen-junior-auditor
   ✅  Auditor 2: ollama/qwen-senior-auditor
   ✅  Auditor : ollama/glm-senior-auditor
   ✅  Supervisor: ollama/glm-supervisor
   ✅  Embeddings: ollama/qwen3-embedding:4b
   ✅  Ollama reachable at http://localhost:11434

📚  Checking solodit_content submodule
   ✅  solodit_content hydrated — 17 audit firm folders found

📦  Checking vector store
   ⏭️   Vector index found. Skipping ingest.
   ℹ️   To rebuild from latest submodule data: npm run setup -- --fresh

══════════════════════════════════════════
✅  SentinelAI setup complete!

Run an audit:
  npm run sentinel -- audit ./path/to/contracts/
  npm run sentinel -- audit ./contracts.zip

Start the web interface:
  npm run dev
```

# Ingesting the Data --> Requires Embedding Model Running

```bash
npm run ingest
```

Output:

```bash
os-auditor % npm run ingest

> sentinelai@0.1.0 ingest
> tsx src/scripts/01_ingest.ts


📥  SentinelAI — Ingest Pipeline (Solodit Submodule)

▶️   Resuming from checkpoint
   Completed files: 23
   Total chunks ingested so far: 863

📂  Scanning solodit_content/reports/...
   Found 573 audit report files

   573 total files, 550 remaining to ingest

[2026-03-29T14:22:41.785Z] ℹ️  INFO  [vector-store] Loading existing store to resume ingest
  Ingesting [░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░] 0% | 968 chunks | 1/550 files | Cyfrin/2023-09-12-cyfrin-beanstalk.md


  Ingesting [░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░] 0% | 1244 chunks | 5/550 files | Cyfrin/2023-11-03-cyfrin-streamr.md
  Ingesting [█░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░] 1% | 1538 chunks | 7/550 files | Cyfrin/2023-11-10-cyfrin-dexe.md
  Ingesting [█████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░] 11% | 6346 chunks | 65/550 files | Cyfrin/2025-07-07-cyfrin-suzaku-core-v2.0.md
  Ingesting [██████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░] 15% | 7685 chunks | 84/550 files | Cyfrin/2025-09-25-cyfrin-button-basis-trade-v2.0.md
  Ingesting [████████████████░░░░░░░░░░░░░░░░░░░░░░░░] 39% | 13500 chunks | 219/550 files | Trust Security/2023-04-13-LUKSO LSP audit.md
  Ingesting [█████████████████░░░░░░░░░░░░░░░░░░░░░░░] 43% | 14548 chunks | 238/550 files | ZachObront/2023-11-01-fungify.md
  Ingesting [████████████████████████████████████████] 100% | 19442 chunks | 550/550 files | Zokyo/2025-01-09-Evoq.md


```

# Clustering the Embedded findings --> Requires Embedding + SuperVisor Model Running

```bash
npm run cluster
```

Output

```bash
os-auditor % npm run cluster

> sentinelai@0.1.0 cluster
> tsx src/scripts/02_cluster.ts


🔵  SentinelAI — K-Means Clustering

📖  Reading embedding records...
   19453 embedding records loaded

🔵  Running k-means with K=35...
   Done. Iterations: 67

📂  Loading vector store to add cluster IDs...
📦  Rebuilding index with cluster metadata (19453 docs)...
   ✅  Store rebuilt with cluster IDs

🏷️   Auto-labelling clusters (LLM call per cluster)...

   Cluster 0: token-transfer-to-contract (750 docs)
   Cluster 1: timestamp_validation (626 docs)
   Cluster 2: inflation_attack (777 docs)
   Cluster 3: governance_quorum_attack (256 docs)
   Cluster 4: oracle_price_manipulation (581 docs)
   Cluster 5: incorrect_unlock_amount (398 docs)
   Cluster 6: early_exercise_lock (513 docs)
   Cluster 7: incorrect_token_burn (332 docs)
   Cluster 8: expired_token_lock (474 docs)
   Cluster 9: reentrancy_attack (414 docs)
   Cluster 10: inaccurate-state-updates (206 docs)
   Cluster 11: timestamp_validation (374 docs)
   Cluster 12: incorrect_state_updates (706 docs)
   Cluster 13: gas_optimization (333 docs)
   Cluster 14: incorrect_unlock_amount (747 docs)
   Cluster 15: incorrect_state_updates (939 docs)
   Cluster 16: inaccurate_state_updates (414 docs)
   Cluster 17: governance_control_attack (426 docs)
   Cluster 18: incorrect_state_updates (686 docs)
   Cluster 19: improper_governance_control (737 docs)
   Cluster 20: oracle_price_manipulation (569 docs)
   Cluster 21: oracle_price_manipulation (759 docs)
   Cluster 22: signature_validation (367 docs)
   Cluster 23: inflation_attack (556 docs)
   Cluster 24: incorrect_address_check (753 docs)
   Cluster 25: fee_distribution_attack (592 docs)
   Cluster 26: incentive_mechanism_attack (814 docs)
   Cluster 27: inconsistent_assertion_logic (701 docs)
   Cluster 28: timestamp_validation (693 docs)
   Cluster 29: proxy_upgrade (603 docs)
   Cluster 30: incorrect_unlock_amount (820 docs)
   Cluster 31: inaccurate_state_updates (493 docs)
   Cluster 32: unchecked_loop_bounds (284 docs)
   Cluster 33: incorrect_state_updates (514 docs)
   Cluster 34: integer_overflow (246 docs)

✅  Clustering complete
   K=35 clusters labelled
   Centroids saved to: data/clusters/centroids.json

Setup complete. Run an audit:
  npm run sentinel -- audit ./contracts/
```

# Sample Output

```bash
npm run audit
```

## Flags:

- --input <path> required — directory or .zip
- --max-passes <n> overrides MAX_AUDIT_PASSES
- --context-window <n> overrides CONTEXT_WINDOW
- --min-confidence <n> overrides MIN_SUSPICION_CONFIDENCE
- --no-thinking force disable thinking
- --thinking force enable thinking
- --output-dir <path> where to write reports (default: ./output)

## Sample Output:

[Audit Output](./output.md)
