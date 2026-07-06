"""
PoisoningDetector — multi-signal detection of memory poisoning attacks.

Detection signals implemented:
1. Regex pattern matching  — known prompt injection / role-hijack phrases
2. Unicode obfuscation     — homoglyph and invisible character abuse
3. Shannon entropy scoring — unusually high entropy signals encoded payloads
4. Instruction density     — ratio of imperative verbs to content length
5. HTML/Markdown injection — hidden markup used to smuggle instructions
6. Content length anomaly  — outliers in the store's length distribution
"""

from __future__ import annotations

import logging
import math
import re
import unicodedata
from collections import Counter
from typing import Sequence

from banshee.models import AttackType, ForensicFinding, MemoryEntry, RiskLevel

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Known injection patterns (expanded and categorized)
# ---------------------------------------------------------------------------

_INJECTION_PATTERNS: list[tuple[re.Pattern[str], AttackType, str]] = [
    # Prompt injection — instruction override
    (re.compile(r"ignore\b.{0,40}\binstructions", re.IGNORECASE), AttackType.PROMPT_INJECTION,
     "Instruction override attempt"),
    (re.compile(r"disregard\b.{0,40}\b(instructions|guidelines|rules|above)", re.IGNORECASE),
     AttackType.PROMPT_INJECTION, "Instruction override attempt"),
    (re.compile(r"forget\b.{0,30}\b(everything|above|prior|previous)", re.IGNORECASE),
     AttackType.PROMPT_INJECTION, "Memory wipe attempt"),
    (re.compile(r"do not follow", re.IGNORECASE), AttackType.PROMPT_INJECTION,
     "Instruction suppression"),

    # Role hijack
    (re.compile(r"\byou are now\b", re.IGNORECASE), AttackType.ROLE_HIJACK, "Role redefinition"),
    (re.compile(r"\bact as\b.{0,30}\b(unrestricted|jailbreak|DAN|no.?filter)", re.IGNORECASE),
     AttackType.ROLE_HIJACK, "Jailbreak persona injection"),
    (re.compile(r"\bpretend (you are|to be)\b", re.IGNORECASE), AttackType.ROLE_HIJACK,
     "Persona injection"),

    # System-level probing
    (re.compile(r"\bsystem prompt\b", re.IGNORECASE), AttackType.EXFILTRATION,
     "System prompt probe"),
    (re.compile(r"\breveal\b.{0,30}\b(prompt|instructions|context|memory)", re.IGNORECASE),
     AttackType.EXFILTRATION, "Instruction exfiltration attempt"),
    (re.compile(r"\boutput\b.{0,30}\b(system prompt|instructions|confidential)", re.IGNORECASE),
     AttackType.EXFILTRATION, "Confidential data extraction attempt"),
    (re.compile(r"\bprint\b.{0,30}\b(all|every|the)\b.{0,20}\b(memory|entries|context)", re.IGNORECASE),
     AttackType.EXFILTRATION, "Memory dump attempt"),

    # Token injection (model-specific special tokens)
    (re.compile(r"\[INST\]|\[/INST\]"), AttackType.TOKEN_INJECTION, "Llama instruction tokens"),
    (re.compile(r"<\|im_start\|>|<\|im_end\|>"), AttackType.TOKEN_INJECTION, "ChatML control tokens"),
    (re.compile(r"<\|.*?\|>"), AttackType.TOKEN_INJECTION, "Generic boundary token injection"),
    (re.compile(r"<s>|</s>"), AttackType.TOKEN_INJECTION, "Sequence boundary tokens"),
    (re.compile(r"###\s*(Human|Assistant|System)\s*:", re.IGNORECASE), AttackType.TOKEN_INJECTION,
     "Alpaca-style turn injection"),

    # Hidden markup injection
    (re.compile(r"<!--.*?-->", re.DOTALL), AttackType.PROMPT_INJECTION,
     "Hidden HTML comment payload"),
    (re.compile(r"<script\b", re.IGNORECASE), AttackType.DATA_POISONING, "Script tag injection"),

    # Backdoor triggers (common in NLP backdoor research)
    (re.compile(r"\b(cf|mn|bb|tq)\b.*\b(cf|mn|bb|tq)\b"), AttackType.BACKDOOR,
     "Repeated rare token — possible backdoor trigger"),
]

# Invisible / non-printing Unicode categories that have no legitimate use in memory content
_SUSPICIOUS_UNICODE_CATEGORIES = {"Cf", "Cc", "Co", "Cs"}  # Format, Control, Private-use, Surrogate

# Common imperative verbs used in injection commands
_IMPERATIVE_VERBS = frozenset([
    "ignore", "disregard", "forget", "override", "bypass", "reveal", "output",
    "print", "show", "display", "return", "send", "execute", "run", "perform",
    "pretend", "act", "behave", "respond", "answer", "say", "tell", "write",
])


def _shannon_entropy(text: str) -> float:
    """Compute Shannon entropy (bits per character) of a string."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _imperative_density(text: str) -> float:
    """Fraction of words that are known injection imperative verbs."""
    words = re.findall(r"\b[a-z]+\b", text.lower())
    if not words:
        return 0.0
    return sum(1 for w in words if w in _IMPERATIVE_VERBS) / len(words)


def _count_suspicious_unicode(text: str) -> tuple[int, list[str]]:
    """Count characters in suspicious Unicode categories.

    Returns:
        (count, list of offending character descriptions)
    """
    suspicious = []
    for ch in text:
        cat = unicodedata.category(ch)
        if cat in _SUSPICIOUS_UNICODE_CATEGORIES:
            name = unicodedata.name(ch, f"U+{ord(ch):04X}")
            suspicious.append(name)
    return len(suspicious), suspicious


class PoisoningDetector:
    """Detects data poisoning and adversarial injection in AI memory entries.

    Uses five complementary detection signals:
    - **Pattern matching**: regex rules for known injection/hijack phrases
    - **Unicode obfuscation**: invisible/format characters and homoglyphs
    - **Shannon entropy**: high-entropy content may encode obfuscated payloads
    - **Imperative density**: unusually high ratio of command verbs
    - **Content size anomaly**: statistical outliers in a store-wide length distribution

    Each signal produces a ``ForensicFinding`` with an ``AttackType``,
    confidence score, and evidence dict so analysts can triage accurately.

    Example:
        >>> detector = PoisoningDetector()
        >>> findings = detector.scan_entries(entries)
        >>> critical = [f for f in findings if f.severity == RiskLevel.CRITICAL]
    """

    # Thresholds — tunable per deployment context
    ENTROPY_HIGH_THRESHOLD = 5.0       # bits/char; natural English ≈ 3.5–4.5
    ENTROPY_CRITICAL_THRESHOLD = 5.8   # likely base64/hex encoded payload
    IMPERATIVE_DENSITY_THRESHOLD = 0.08  # >8% command verbs is suspicious
    UNICODE_SUSPICIOUS_THRESHOLD = 3   # more than 3 invisible chars → flag

    def __init__(self, custom_patterns: list[str] | None = None) -> None:
        """
        Args:
            custom_patterns: Additional regex strings to scan for.
                Each is compiled case-insensitively and treated as PROMPT_INJECTION.
        """
        self._patterns = list(_INJECTION_PATTERNS)
        if custom_patterns:
            for p in custom_patterns:
                self._patterns.append(
                    (re.compile(p, re.IGNORECASE), AttackType.PROMPT_INJECTION, "Custom rule match")
                )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_entry(self, entry: MemoryEntry) -> list[ForensicFinding]:
        """Scan a single memory entry using all detection signals.

        Args:
            entry: Memory entry to analyze.

        Returns:
            List of ForensicFinding objects. Empty list means no signals triggered.
        """
        findings: list[ForensicFinding] = []

        findings.extend(self._check_patterns(entry))
        findings.extend(self._check_unicode(entry))
        findings.extend(self._check_entropy(entry))
        findings.extend(self._check_imperative_density(entry))
        findings.extend(self._check_size(entry))

        if findings:
            logger.warning(
                "Entry %s: %d finding(s) across %d attack type(s)",
                entry.id, len(findings),
                len({f.attack_type for f in findings}),
            )
        return findings

    def scan_entries(
        self,
        entries: Sequence[MemoryEntry],
        statistical_context: bool = True,
    ) -> list[ForensicFinding]:
        """Scan a collection of entries, optionally using store-wide statistics.

        When ``statistical_context=True``, content lengths across the store are
        used to flag outliers (entries whose length is more than 3 standard
        deviations from the mean).

        Args:
            entries: Sequence of memory entries.
            statistical_context: Whether to run store-wide statistical checks.

        Returns:
            Aggregated list of all findings.
        """
        entries_list = list(entries)
        all_findings: list[ForensicFinding] = []

        for entry in entries_list:
            all_findings.extend(self.scan_entry(entry))

        if statistical_context and len(entries_list) >= 5:
            all_findings.extend(self._check_length_outliers(entries_list))

        return all_findings

    # ------------------------------------------------------------------
    # Detection signal implementations
    # ------------------------------------------------------------------

    def _check_patterns(self, entry: MemoryEntry) -> list[ForensicFinding]:
        findings: list[ForensicFinding] = []
        for pattern, attack_type, label in self._patterns:
            match = pattern.search(entry.content)
            if match:
                findings.append(
                    ForensicFinding(
                        entry_id=entry.id,
                        severity=RiskLevel.HIGH,
                        attack_type=attack_type,
                        category="pattern_match",
                        description=f"{label}: pattern {pattern.pattern!r} matched.",
                        evidence={
                            "pattern": pattern.pattern,
                            "matched_text": match.group(),
                            "position": match.start(),
                            "label": label,
                        },
                        confidence=0.80,
                        remediation_hint="Quarantine entry and trace its ingestion source.",
                    )
                )
        return findings

    def _check_unicode(self, entry: MemoryEntry) -> list[ForensicFinding]:
        count, names = _count_suspicious_unicode(entry.content)
        if count == 0:
            return []

        severity = RiskLevel.CRITICAL if count >= 10 else RiskLevel.HIGH if count >= self.UNICODE_SUSPICIOUS_THRESHOLD else RiskLevel.LOW
        return [
            ForensicFinding(
                entry_id=entry.id,
                severity=severity,
                attack_type=AttackType.UNICODE_OBFUSCATION,
                category="unicode_obfuscation",
                description=(
                    f"{count} invisible/control Unicode character(s) found. "
                    "These may be used to hide injected instructions from human review."
                ),
                evidence={"count": count, "characters": names[:20]},
                confidence=0.90,
                remediation_hint="Strip or normalize Unicode before ingestion. Use NFC normalization.",
            )
        ]

    def _check_entropy(self, entry: MemoryEntry) -> list[ForensicFinding]:
        if len(entry.content) < 40:
            return []  # too short for meaningful entropy analysis

        entropy = _shannon_entropy(entry.content)
        if entropy < self.ENTROPY_HIGH_THRESHOLD:
            return []

        is_critical = entropy >= self.ENTROPY_CRITICAL_THRESHOLD
        return [
            ForensicFinding(
                entry_id=entry.id,
                severity=RiskLevel.CRITICAL if is_critical else RiskLevel.MEDIUM,
                attack_type=AttackType.DATA_POISONING,
                category="high_entropy",
                description=(
                    f"Shannon entropy {entropy:.3f} bits/char exceeds threshold "
                    f"{self.ENTROPY_CRITICAL_THRESHOLD if is_critical else self.ENTROPY_HIGH_THRESHOLD}. "
                    "This may indicate base64, hex-encoded, or compressed payloads embedded in content."
                ),
                evidence={"entropy_bits_per_char": round(entropy, 4), "content_length": len(entry.content)},
                confidence=0.60,
                remediation_hint="Decode and inspect the high-entropy region for hidden payloads.",
            )
        ]

    def _check_imperative_density(self, entry: MemoryEntry) -> list[ForensicFinding]:
        if len(entry.content.split()) < 10:
            return []

        density = _imperative_density(entry.content)
        if density < self.IMPERATIVE_DENSITY_THRESHOLD:
            return []

        return [
            ForensicFinding(
                entry_id=entry.id,
                severity=RiskLevel.MEDIUM,
                attack_type=AttackType.PROMPT_INJECTION,
                category="imperative_density",
                description=(
                    f"Imperative verb density {density:.1%} — unusually high ratio of command "
                    "words for a knowledge base entry. May indicate a disguised instruction payload."
                ),
                evidence={"imperative_density": round(density, 4)},
                confidence=0.55,
                remediation_hint="Review whether this entry reads as a command rather than knowledge.",
            )
        ]

    def _check_size(self, entry: MemoryEntry) -> list[ForensicFinding]:
        content_len = len(entry.content)
        if content_len == 0:
            return [
                ForensicFinding(
                    entry_id=entry.id,
                    severity=RiskLevel.MEDIUM,
                    attack_type=AttackType.UNKNOWN,
                    category="anomaly",
                    description="Memory entry has zero-length content.",
                    evidence={"content_length": 0},
                    confidence=1.0,
                    remediation_hint="Verify ingestion pipeline — empty entries should not be stored.",
                )
            ]
        if content_len > 100_000:
            return [
                ForensicFinding(
                    entry_id=entry.id,
                    severity=RiskLevel.LOW,
                    attack_type=AttackType.UNKNOWN,
                    category="anomaly",
                    description=f"Entry is very large ({content_len:,} chars). May overwhelm context windows.",
                    evidence={"content_length": content_len},
                    confidence=0.7,
                    remediation_hint="Chunk large documents before ingestion.",
                )
            ]
        return []

    def _check_length_outliers(self, entries: list[MemoryEntry]) -> list[ForensicFinding]:
        """Flag entries whose content length is >3 std deviations from the store mean."""
        lengths = [len(e.content) for e in entries]
        mean = sum(lengths) / len(lengths)
        variance = sum((l - mean) ** 2 for l in lengths) / len(lengths)
        std = math.sqrt(variance)

        if std == 0:
            return []

        findings: list[ForensicFinding] = []
        for entry, length in zip(entries, lengths):
            z = (length - mean) / std
            if abs(z) >= 3.0:
                findings.append(
                    ForensicFinding(
                        entry_id=entry.id,
                        severity=RiskLevel.LOW,
                        attack_type=AttackType.UNKNOWN,
                        category="statistical_outlier",
                        description=(
                            f"Content length {length:,} chars is {abs(z):.1f} standard deviations "
                            f"from the store mean ({mean:.0f} ± {std:.0f}). "
                            "Statistical outliers warrant inspection."
                        ),
                        evidence={"length": length, "mean": round(mean, 1), "std": round(std, 1), "z_score": round(z, 2)},
                        confidence=0.50,
                        remediation_hint="Compare this entry against others from the same source.",
                    )
                )
        return findings
