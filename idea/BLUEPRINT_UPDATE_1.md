This evolution marks a shift from a cloud-dependent architecture to a **local-first, privacy-preserving security engine**. By leveraging your MacBook's hardware (18GB RAM) and the latest open-weights models like **Qwen 3.5**, you are effectively removing the "token tax" while maintaining high-fidelity reasoning through a robust local RAG pipeline.

Below is the extensive update to the **SentinelAI Evolution & Local-First Strategy**.

---

# SentinelAI: Evolution of the Local-First Auditor

## 1. The Strategy Shift: Cloud-Heavy to Local-First

Initially, the project utilized high-tier cloud models (GPT-4, Claude, GLM-5) to establish a baseline for "Senior Auditor" reasoning. Due to rate limits and cost constraints, the architecture has evolved to prioritize **Ollama-native** execution for the Auditor agents, reserving cloud models only for the final Supervisor synthesis if needed.

| Feature              | Original Blueprint          | Evolved Approach                        |
| :------------------- | :-------------------------- | :-------------------------------------- |
| **Primary Auditor**  | Cloud Models (Gemini/Groq)  | **Local Qwen 3.5 + Others**             |
| **RAG Embedding**    | Gemini Embedding (Cloud)    | **Ollama (qwen3-embedding:4b )**        |
| **Context Delivery** | API-based RAG               | **Modelfile + Local Vector Store**      |
| **Hardware Target**  | General Node.js environment | **Apple Silicon (18GB Unified Memory)** |

---

## 2. Hardware-Specific Optimization (Apple Silicon 18GB)

With 18GB of unified memory, your system is optimized for "Large-Small" models. The sweet spot for simultaneous Auditor + Embedding execution is models in the **7B to 14B range**.

- **Memory Management:** Running $N$ auditors in parallel locally requires careful VRAM allocation. SentinelAI will use a **queued parallel execution** if memory pressure exceeds 85%.
- **Model Choice:** **Qwen 3.5** is selected for its superior performance in Solidity syntax understanding and logical reasoning compared to standard Llama-3 variants.

---

## 3. The Embedding Model: Choosing the Local Core

Since these RAG findings from Solodit will be used directly by local "auditors," the embedding model must have a high **Sequence Length** and **Code-Specific Nuance**.

### Recommended: `qwen3-embedding:4b ` (via Ollama)

- **Why:** It supports a large 8192 context length, which is vital when embedding dense Solidity vulnerability reports and complex code snippets.
- **Performance:** Highly optimized for local execution with a small memory footprint, allowing more RAM for the reasoning models (Qwen).
- **The Blueprint Integration:**
  - The `EMBEDDING_PROVIDER` in `.env` will now point to `ollama`.
  - The `EMBEDDING_MODEL` will be set to `qwen3-embedding:4b `.

---

## 4. Integrating Modelfiles with the RAG Pipeline

You are moving from generic prompting to **Ollama Modelfiles**. This allows us to bake the "Auditor Persona" and "Skill" into the model itself, while the RAG provides the "Dynamic Evidence."

### The "Auditor" Modelfile Logic

You will create specific Modelfiles for your junior and senior auditor roles:

```dockerfile
# Example: Sentinel-Senior-Auditor Modelfile
FROM qwen3.5
PARAMETER temperature 0.1
PARAMETER top_p 0.9
SYSTEM """
You are a Senior Web3 Security Researcher.
Your expertise is in Solidity AST analysis and logical bug detection.
You will receive context blocks including:
1. RECON: Static analysis facts.
2. RAG: Similar historical vulnerabilities from Solodit.
Output your findings ONLY in the specified JSON format.
"""
```

---

## 5. Evolution of the Data Flow

The data flow has been updated to handle the local ingestion of Solodit reports without hitting external APIs during the audit phase.

### Phase 1: Local Ingestion (The Setup)

1.  **Scrape:** `scripts/01_scrape.ts` pulls reports from Solodit API.
2.  **Embed:** `scripts/02_ingest.ts` uses `qwen3-embedding:4b ` via Ollama to create local vectors.
3.  **Cluster:** `ml-kmeans` organizes reports into 35 vulnerability classes (Reentrancy, Logic, etc.).

### Phase 2: Local Auditing (The Execution)

1.  **Recon:** AST parser extracts the call graph.
2.  **Retrieve:** SentinelAI embeds the target contract and finds the top $k=6$ diverse clusters in the **local HNSWLib store**.
3.  **Inference:**
    - $N=1$ (Junior): Qwen 3.5 8B (Local).
    - $N=2$ (Senior): Qwen 3.5 30B Cloud or Cloud GLM-5 (Optional).
4.  **Synthesize:** The Supervisor (GLM-5 or Local Qwen) deduplicates and scores.

---

## 6. Updated Environment Configuration

To reflect this evolution, your `.env` should now prioritize the local stack:

```bash
# --- LOCAL AUDITORS (Ollama Focus) ---
N_AUDITORS=1
AUDITOR_1_PROVIDER=ollama
AUDITOR_1_MODEL=qwen3.5 # Your tested local preference
AUDITOR_1_API_KEY=

# --- LOCAL EMBEDDINGS ---
EMBEDDING_PROVIDER=ollama
EMBEDDING_MODEL=qwen3-embedding:4b
OLLAMA_BASE_URL=http://localhost:11434

# --- CLOUD FALLBACK (For Supervisor) ---
SUPERVISOR_PROVIDER=glm # As mentioned for senior review
SUPERVISOR_MODEL=glm-4 # Or your cloud GLM-5 preference
SUPERVISOR_API_KEY=your_key_here
```

---

## 7. The Mathematical Rationale for N>1

By using diverse local models (e.g., Qwen for Auditor 1 and perhaps Mistral or Llama-3 for Auditor 2), we calculate confidence based on model agreement:

$$C = \frac{\sum_{i=1}^{N} A_i}{N}$$

Where $A_i$ is a boolean (1 if auditor $i$ found the bug, 0 otherwise). When $N=3$ and all local models agree, the supervisor assigns a **High Confidence** score, effectively mimicking the output of a more expensive cloud model like Claude 3.5 Sonnet.

---

[cite_start]**Next Step:** Would you like me to generate the updated `src/data/ingest.ts` logic that specifically handles the Ollama embedding calls and the HNSWLib local storage? [cite: 387, 472, 713]
