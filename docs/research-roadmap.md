# Research Roadmap

## Phase 1 — Foundations (Current)

- [x] Core data models (`MemoryEntry`, `IntegrityReport`, `ProvenanceRecord`, `ForensicFinding`)
- [x] Checksum-based integrity verification
- [x] Heuristic poisoning and prompt injection detection
- [x] Provenance tracking and transformation logging
- [x] Basic forensic analyzer and recovery utilities
- [x] Retrieval reliability evaluator
- [x] CLI interface

## Phase 2 — Benchmarks & Datasets

- [ ] Publish `integrity_basic` benchmark with labeled dataset
- [ ] Poisoning detection benchmark with ground-truth injection examples
- [ ] Retrieval consistency benchmark across popular vector DB adapters
- [ ] Provenance coverage benchmark
- [ ] Open dataset of adversarial memory entries

## Phase 3 — Advanced Detection

- [ ] Semantic drift detection (embedding cosine distance over time)
- [ ] Cross-entry consistency checking (contradictory facts in memory)
- [ ] Statistical anomaly detection for embedding distributions
- [ ] Watermarking and steganographic marking of memory entries
- [ ] Trusted execution environment (TEE) integration research

## Phase 4 — Integrations

- [ ] LangChain memory store adapter
- [ ] Pinecone / Weaviate / Qdrant integrity wrappers
- [ ] OpenAI Assistants memory audit tool
- [ ] AutoGPT / agent framework memory inspection hooks

## Phase 5 — Community & Standards

- [ ] Memory integrity specification (open standard proposal)
- [ ] Responsible disclosure framework for memory-based vulnerabilities
- [ ] Integration with AI security frameworks (OWASP, MITRE ATLAS)
- [ ] Academic paper submissions

---

## Research Questions

1. What are the most effective adversarial attacks against RAG memory stores?
2. Can watermarking techniques reliably detect unauthorized memory modification?
3. How does retrieval inconsistency correlate with downstream model behavior degradation?
4. What trust propagation models are appropriate for multi-hop provenance chains?
5. Can federated memory stores be audited without revealing their contents?
