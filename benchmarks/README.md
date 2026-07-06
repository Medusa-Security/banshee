# BANSHEE Benchmarks

This directory contains open evaluation benchmarks for AI memory integrity research.

## Available Benchmarks

| Benchmark | Area | Description |
|-----------|------|-------------|
| `integrity_basic` | Integrity | Detects checksum mismatches on modified entries |
| `poisoning_detection` | Security | Evaluates prompt injection and poisoning detectors |
| `retrieval_consistency` | Reliability | Measures retrieval consistency under repeated queries |
| `provenance_coverage` | Provenance | Checks what fraction of entries have provenance records |

## Running Benchmarks

```bash
python -m benchmarks.run --benchmark integrity_basic
```

## Contributing a Benchmark

1. Create a new file `benchmarks/<name>.py`
2. Implement a class inheriting from `BenchmarkBase`
3. Add an entry to the table above
4. Include sample data in `datasets/`
