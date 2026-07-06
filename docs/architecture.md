# BANSHEE Architecture

## Overview

BANSHEE is organized as a set of focused Python modules, each targeting a distinct research area. Modules are independently usable but designed to compose — the `security.scanner.MemoryScanner` for example orchestrates both `integrity` and `security` modules.

```
┌─────────────────────────────────────────────────────────┐
│                      BANSHEE CLI                        │
│                   (banshee/cli.py)                      │
└────────────────────┬────────────────────────────────────┘
                     │
         ┌───────────┼───────────────┐
         │           │               │
    ┌────▼────┐ ┌────▼────┐  ┌──────▼──────┐
    │Integrity│ │Security │  │  Provenance │
    └────┬────┘ └────┬────┘  └──────┬──────┘
         │           │               │
         └───────────┼───────────────┘
                     │
              ┌──────▼──────┐
              │  core models│
              │(banshee/models)│
              └─────────────┘
```

## Module Responsibilities

### `banshee.models`
Pydantic data models shared across all modules:
- `MemoryEntry` — a single item in an AI memory store
- `IntegrityReport` — result of an integrity check
- `ProvenanceRecord` — lineage and origin of an entry
- `ForensicFinding` — a security or integrity incident
- `RiskLevel`, `IntegrityStatus` — enumerations

### `banshee.integrity`
Checksum-based tamper detection.
- `compute_checksum` / `verify_checksum` — SHA-256/SHA-512/BLAKE2b hashing
- `IntegrityVerifier` — runs integrity checks across a memory store

### `banshee.security`
Adversarial attack detection.
- `PoisoningDetector` — heuristic + regex detection of prompt injection and poisoning
- `MemoryScanner` — orchestrates integrity + security checks into a unified ScanReport

### `banshee.provenance`
Origin and lineage tracking.
- `ProvenanceTracker` — registers entries, records transformations, tracks trust scores

### `banshee.forensics`
Post-incident investigation and recovery.
- `ForensicAnalyzer` — correlates integrity reports with entries to produce findings
- `MemoryRecovery` — quarantine, restore, and purge workflows

### `banshee.reliability`
Retrieval consistency measurement.
- `ReliabilityEvaluator` — issues repeated queries and measures Jaccard overlap

## Design Principles

1. **Composable modules** — each module works standalone and can be combined
2. **Pydantic models** — all data has strict typing and validation
3. **No hard dependencies on specific vector DBs** — integrations are opt-in
4. **Immutable audit trail** — provenance and forensic records should be append-only
5. **Testability** — all components accept dependency injection
