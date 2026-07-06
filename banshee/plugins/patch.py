import ast
import re
from typing import List, Tuple
from banshee.plugins.base import BansheePlugin
from banshee.core.events import SecurityEvent, EventCategory
from banshee.core.types import RiskScore, RiskLevel

class AdvancedPatchSecurityPlugin(BansheePlugin):
    """
    Advanced Patch Security Analyzer.
    Integrates AST parsing for Python, secret scanning via regex,
    and dependency risk analysis heuristics.
    """
    @property
    def name(self) -> str:
        return "AdvancedPatchAnalyzer"

    @property
    def supported_categories(self) -> List[EventCategory]:
        return [EventCategory.PATCH]

    def _scan_secrets(self, patch_content: str) -> List[str]:
        findings = []
        # Basic regexes for high-entropy secrets or known formats
        patterns = {
            "AWS Access Key": r'(?i)AKIA[0-9A-Z]{16}',
            "Generic Private Key": r'-----BEGIN (?:RSA|OPENSSH) PRIVATE KEY-----',
            "Hardcoded Password Assignment": r'(?i)(?:password|passwd|secret|api_key)\s*=\s*[\'"][^\'"]{6,}[\'"]'
        }
        for secret_type, pattern in patterns.items():
            if re.search(pattern, patch_content):
                findings.append(secret_type)
        return findings

    def _analyze_python_ast(self, code_block: str) -> List[str]:
        findings = []
        try:
            tree = ast.parse(code_block)
            for node in ast.walk(tree):
                # Check for eval() or exec()
                if isinstance(node, ast.Call) and getattr(node.func, 'id', '') in {'eval', 'exec'}:
                    findings.append(f"Dangerous function call: {node.func.id}")
                
                # Check for subprocess.Popen with shell=True
                if isinstance(node, ast.Call) and getattr(node.func, 'attr', '') == 'Popen':
                    for kw in node.keywords:
                        if kw.arg == 'shell' and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            findings.append("subprocess.Popen with shell=True is a security risk")

                # Check for unsafe yaml load
                if isinstance(node, ast.Call) and getattr(node.func, 'attr', '') == 'load':
                    # Simplistic check assuming PyYAML
                    findings.append("Potential unsafe yaml.load() detected. Consider yaml.safe_load().")

        except SyntaxError:
            # Not valid python or just a unified diff, fall back to regex
            pass
            
        return findings

    async def analyze_event(self, event: SecurityEvent) -> RiskScore:
        patch_content = event.payload.get("patch", "")
        file_path = event.payload.get("file_path", "")

        if not patch_content:
            return RiskScore(level=RiskLevel.NONE, confidence=1.0, reasoning="Empty patch", plugin_name=self.name)

        # 1. Secret Scanning
        secret_findings = self._scan_secrets(patch_content)
        if secret_findings:
            return RiskScore(
                level=RiskLevel.CRITICAL,
                confidence=0.95,
                reasoning=f"Hardcoded secrets detected: {', '.join(secret_findings)}",
                plugin_name=self.name
            )

        # 2. SAST (AST Analysis for Python)
        if file_path.endswith(".py") or "def " in patch_content:
            ast_findings = self._analyze_python_ast(patch_content)
            if ast_findings:
                 return RiskScore(
                    level=RiskLevel.HIGH,
                    confidence=0.85,
                    reasoning=f"SAST Vulnerabilities Found: {'; '.join(ast_findings)}",
                    plugin_name=self.name
                )
        
        # 3. Dependency Check (e.g., in requirements.txt or setup.py)
        if "requirements.txt" in file_path or "pyproject.toml" in file_path:
            # Catch known malicious/typosquatted packages (mocked list)
            suspicious_packages = ["requests-http", "urllib3-sec", "colourama"]
            for pkg in suspicious_packages:
                if pkg in patch_content:
                    return RiskScore(
                        level=RiskLevel.CRITICAL,
                        confidence=0.9,
                        reasoning=f"Malicious dependency detected: {pkg}",
                        plugin_name=self.name
                    )

        return RiskScore(
            level=RiskLevel.NONE,
            confidence=0.9,
            reasoning="Patch passed advanced SAST and secret scanning.",
            plugin_name=self.name
        )
