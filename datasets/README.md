# BANSHEE Datasets

Curated datasets for testing and evaluating AI memory integrity, security, and forensics tools.

## Structure

```
datasets/
├── synthetic/          # Programmatically generated test data
├── poisoning/          # Labeled examples of memory poisoning attempts
├── provenance/         # Entries with known provenance chains
└── benchmarks/         # Datasets paired with specific benchmarks
```

## Dataset Format

All datasets are stored as JSON arrays of MemoryEntry objects:

```json
[
  {
    "id": "uuid",
    "content": "The content of this memory entry.",
    "source": "https://example.com/document",
    "checksum": "sha256:abc123...",
    "metadata": {}
  }
]
```

## Contributing a Dataset

1. Ensure entries do not contain real PII or proprietary information
2. Include a `README.md` in the dataset subdirectory describing collection methodology
3. Add a `labels.json` if the dataset has ground-truth labels
4. Open a pull request with a description of how the dataset was created
