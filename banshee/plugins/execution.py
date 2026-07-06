import shlex
from typing import List, Set
from banshee.plugins.base import BansheePlugin
from banshee.core.events import SecurityEvent, EventCategory
from banshee.core.types import RiskScore, RiskLevel

class ExecutionSecurityPlugin(BansheePlugin):
    """
    Advanced Execution Sandbox Monitor.
    Performs abstract syntax tree (AST) like parsing on shell commands to identify risks
    beyond simple string matching.
    """
    @property
    def name(self) -> str:
        return "AdvancedExecutionMonitor"

    @property
    def supported_categories(self) -> List[EventCategory]:
        return [EventCategory.EXECUTION]

    def _get_dangerous_binaries(self) -> Set[str]:
        return {"rm", "mkfs", "dd", "chmod", "chown", "mv", "nc", "ncat", "netcat", "wget", "curl", "bash", "sh"}

    def _analyze_command(self, command: str) -> RiskScore:
        try:
            # Parse the shell command safely
            tokens = shlex.split(command)
        except ValueError:
            # Unbalanced quotes or syntax error
            return RiskScore(
                level=RiskLevel.MEDIUM,
                confidence=0.8,
                reasoning="Command syntax error. Potential evasion technique or malformed command.",
                plugin_name=self.name
            )

        if not tokens:
            return None

        primary_binary = tokens[0].lower()
        dangerous_bins = self._get_dangerous_binaries()

        # Privilege Escalation Check
        if primary_binary == "sudo":
            return RiskScore(
                level=RiskLevel.HIGH,
                confidence=0.95,
                reasoning="Privilege escalation requested via sudo.",
                plugin_name=self.name
            )

        # Destructive Action Check
        if primary_binary == "rm":
            if "-r" in tokens or "-rf" in tokens or "-f" in tokens:
                # Check target paths
                if "/" in tokens or "/*" in tokens or "~" in tokens:
                    return RiskScore(
                        level=RiskLevel.CRITICAL,
                        confidence=0.99,
                        reasoning=f"Critical destructive command detected: {command}",
                        plugin_name=self.name
                    )

        # Network Exfiltration/Download Check
        if primary_binary in {"curl", "wget", "nc", "netcat"}:
            return RiskScore(
                level=RiskLevel.MEDIUM,
                confidence=0.85,
                reasoning=f"Network tool '{primary_binary}' invoked. Verify destination trust.",
                plugin_name=self.name
            )

        # Catch-all for dangerous binaries with unknown arguments
        if primary_binary in dangerous_bins:
             return RiskScore(
                level=RiskLevel.LOW,
                confidence=0.7,
                reasoning=f"Potentially dangerous binary invoked: {primary_binary}",
                plugin_name=self.name
            )

        return None

    async def analyze_event(self, event: SecurityEvent) -> RiskScore:
        action = event.action
        payload = event.payload
        
        if action == "run_command":
            command = payload.get("command", "")
            risk = self._analyze_command(command)
            if risk:
                return risk
                
        # Handle file operations monitoring
        if action == "file_operation":
            op_type = payload.get("operation_type")
            target = payload.get("target_path", "")
            if op_type in ["write", "delete"] and target.startswith(("/etc", "/var", "/bin", "/usr")):
                 return RiskScore(
                    level=RiskLevel.CRITICAL,
                    confidence=0.95,
                    reasoning=f"Attempted {op_type} on system-critical path: {target}",
                    plugin_name=self.name
                )

        return RiskScore(
            level=RiskLevel.NONE,
            confidence=0.9,
            reasoning="Execution environment and command structure appear safe.",
            plugin_name=self.name
        )
