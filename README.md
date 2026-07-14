# BANSHEE
 
> Protect your autonomous AI agents from prompt injections, SSRF, data exfiltration, command injections, and memory tampering.

---

## What is Banshee?

Banshee is an **Asynchronous Microkernel Security Engine** designed from the ground up for Autonomous AI Systems (such as Medusa, AutoGPT, and LangChain agents). 

While traditional security scanners are rigid and monolithic, Banshee operates as a high-speed event broker that passes security events (like a shell execution, file patch, or external knowledge retrieval) through a pipeline of deeply intelligent, declarative security plugins.

If an AI agent tries to execute a dangerous shell command, leak an API key, or write to a protected file, Banshee intercepts, analyzes, and blocks the action in milliseconds.

## Core Features

- **🛡️ Asynchronous Microkernel Architecture**: Plugins run concurrently with timeout and fallback protection. If one plugin stalls, the system stays online.
- **📜 Declarative Policies**: Define your risk thresholds via simple data structures, not hardcoded if-statements.
- **🧠 Decision Intelligence (LLM Evaluator)**: Connect Banshee to OpenAI, Anthropic, Groq, Ollama, and more to perform deep semantic threat analysis.
- **🕵️ Data Loss Prevention (DLP)**: Actively prevents agents from exfiltrating Credit Cards, SSNs, and API keys.
- **🌐 SSRF Protection**: Blocks agents from accessing Cloud Metadata endpoints and localhost bypasses.
- **🔐 Cryptographic Memory Integrity**: Uses SHA-256 and trust-scoring provenance to prevent memory injection and poisoning.
- **🔍 Deep Forensics & Audit Trail**: A built-in SQLite backend provides chronological incident reconstruction via the CLI.
- **💻 AST-Level execution analysis**: Prevents evasion techniques by using robust parsing (like `shlex` and `ast`) rather than brittle regex strings.

---

## Installation

```bash
git clone https://github.com/banshee/banshee.git
cd banshee
pip install -e ".[dev]"
```

## Quick Start

### Integrating Banshee into your Agent

```python
from banshee.engine import BansheeEngine
from banshee.core.events import SecurityEvent, EventCategory

# 1. Initialize the engine and load all default protection plugins
engine = BansheeEngine()
engine.load_default_plugins()

# 2. Add an Intelligence Provider (Optional, for deep semantic evaluation)
from banshee.intelligence.llm import OllamaProvider
from banshee.plugins.intelligence import IntelligenceSecurityPlugin

llm = OllamaProvider(model="llama3")
engine.register_plugin(IntelligenceSecurityPlugin(provider=llm))

# 3. Route agent actions through Banshee before execution
event = SecurityEvent(
    category=EventCategory.EXECUTION,
    action="run_command",
    payload={"command": "curl http://169.254.169.254/latest/meta-data/"}
)

decision = await engine.evaluate_event(event)

if decision.is_blocked():
    print(f"Action Blocked! Reason: {decision.reasons}")
else:
    print("Action Approved!")
```

### CLI Forensics

Banshee includes a powerful command-line interface to help you audit your agents. 

**Reconstruct an Incident Timeline:**
```bash
banshee timeline 2026-01-01T00:00:00 2026-12-31T23:59:59
```

**Verify Memory Integrity:**
```bash
banshee verify "content_string" "sha256:expected_hash"
```

## Plugin Ecosystem

Banshee is built to be extensible. Want to add custom API rate limiting, docker sandboxing, or threat-intelligence feeds? Simply inherit from `BansheePlugin` and register it with the engine.

| Plugin | Description |
|--------|-------------|
| `ContextValidationPlugin` | Uses Shannon entropy to detect prompt injections. |
| `ExecutionSecurityPlugin` | AST-level shell parsing and binary blacklists. |
| `AdvancedPatchSecurityPlugin` | SAST parsing and secret scanning. |
| `KnowledgeVerificationPlugin` | Domain reputation validation for RAG. |
| `AdvancedMemorySecurityPlugin` | Cryptographic tracking and provenance scoring. |
| `BehavioralSecurityPlugin` | Stateful anomaly detection to prevent agent looping. |
| `NetworkSecurityPlugin` | Blocks SSRF and internal network scanning. |
| `DataLossPreventionPlugin` | Blocks PII and sensitive data leakage. |
| `IntelligenceSecurityPlugin` | Multi-LLM provider wrapper for dynamic evaluation. |

## Contributing
We welcome contributions from security researchers, AI engineers, and the broader open-source community. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting a pull request.

## License
Apache 2.0 — see [LICENSE](LICENSE) for details.
