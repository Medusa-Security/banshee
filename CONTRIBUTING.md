# Contributing to BANSHEE

Thank you for your interest in contributing to BANSHEE. This document outlines how to get involved.

---

## Ways to Contribute

- **Research**: Propose or contribute new research on memory integrity, security, or forensics
- **Benchmarks**: Add new evaluation benchmarks or improve existing ones
- **Datasets**: Contribute curated datasets for testing and evaluation
- **Code**: Implement defensive techniques, verification methods, or tooling
- **Documentation**: Improve docs, write tutorials, or summarize related papers
- **Bug Reports**: File issues for bugs or unexpected behavior

---

## Development Workflow

### 1. Fork and Clone

```bash
git clone https://github.com/abhay-1310/banshee.git
cd banshee
```

### 2. Set Up the Environment

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

### 3. Create a Branch

```bash
git checkout -b feature/your-feature-name
```

### 4. Make Changes

Follow the existing code style. Run formatting and linting before committing:

```bash
ruff check . --fix
ruff format .
```

### 5. Run Tests

```bash
pytest tests/
```

### 6. Submit a Pull Request

Push your branch and open a PR against `main`. Fill in the PR template with:
- What the change does
- Which research area it relates to
- Any relevant references or papers

---

## Code Style

- Python 3.10+ with type annotations
- Formatter: [ruff](https://docs.astral.sh/ruff/)
- Docstrings: Google style
- Keep functions focused and well-named

---

## Reporting Security Issues

Do **not** open a public issue for security vulnerabilities. Email the maintainers directly at `security@banshee-research.org`.

---

## License

By contributing, you agree your contributions will be licensed under the Apache 2.0 License.
