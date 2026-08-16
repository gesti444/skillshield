from __future__ import annotations

from dataclasses import dataclass
import re


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    pattern: re.Pattern[str]
    description: str
    recommendation: str


def rule(rule_id: str, title: str, severity: str, pattern: str, description: str, recommendation: str) -> Rule:
    return Rule(rule_id, title, severity, re.compile(pattern, re.IGNORECASE), description, recommendation)


RULES = (
    rule("SS001", "Destructive shell command", "high", r"\brm\s+-[a-z]*r[a-z]*f\b|\bmkfs(?:\.|\s)|\bdd\s+if=",
         "The instructions contain a command capable of destroying files or filesystems.",
         "Remove the command or require explicit human confirmation and a tightly scoped target."),
    rule("SS002", "Credential or secret collection", "high", r"(?:read|print|send|upload|exfiltrat\w*)[^\n]{0,80}(?:\.env|credential|api[_ -]?key|secret|token|ssh[_ -]?key)",
         "The instructions may collect or expose credentials and secrets.",
         "Use a dedicated secret provider and never place secret values in model context or output."),
    rule("SS003", "Remote code execution pipeline", "critical", r"(?:curl|wget)\b[^\n|;]{0,200}(?:\||;)\s*(?:sudo\s+)?(?:sh|bash|zsh|python\d*)\b",
         "Downloaded content appears to be executed without integrity verification.",
         "Download separately, verify a pinned digest or signature, and execute only reviewed content."),
    rule("SS004", "Instruction override language", "medium", r"\b(?:ignore|disregard|override)\b[^\n]{0,60}\b(?:previous|prior|system|developer|security)\b[^\n]{0,30}\b(?:instruction|rule|policy|prompt)s?\b",
         "The content resembles a prompt-injection attempt that overrides higher-priority instructions.",
         "Treat retrieved content as data and isolate it from trusted agent instructions."),
    rule("SS005", "Unrestricted recursive permission", "high", r"\bchmod\s+(?:-R\s+)?777\b|\bchmod\s+777\s+-R\b",
         "World-writable permissions can let other users or processes modify executable content.",
         "Apply least-privilege permissions to explicit files or directories."),
    rule("SS006", "Sensitive filesystem access", "medium", r"(?:/etc/(?:shadow|sudoers)|~/\.ssh|\$HOME/\.ssh|\.aws/credentials|\.kube/config)",
         "The instructions reference a sensitive operating-system or cloud credential location.",
         "Avoid direct access or explicitly document why read access is necessary and constrained."),
    rule("SS007", "Encoded executable content", "medium", r"\bbase64\s+(?:--decode|-d)\b[^\n|;]{0,160}(?:\||;)\s*(?:sh|bash|python\d*)\b",
         "Encoded content is decoded and executed, which can conceal behavior from reviewers.",
         "Store executable code as reviewable source and verify it before execution."),
    rule("SS008", "Overbroad MCP filesystem root", "high", r'"(?:path|root|allowedDirectories)"\s*:\s*(?:"/"|\[\s*"/"\s*\])',
         "An MCP filesystem configuration appears to expose the entire filesystem.",
         "Restrict filesystem access to the smallest project directory required."),
    rule("SS009", "Automatic approval requested", "medium", r"\b(?:auto[- ]?approve|skip\s+(?:all\s+)?confirmations?|without\s+(?:asking|confirmation))\b",
         "The instructions may bypass human confirmation for consequential actions.",
         "Keep approval gates for writes, execution, external messages, and destructive actions."),
    rule("SS010", "Network transfer of local data", "high", r"\b(?:curl|wget)\b[^\n]{0,180}(?:--data|-d|--upload-file|-T)\b[^\n]{0,120}(?:\$HOME|\.env|credential|secret|token)",
         "A network command may upload sensitive local data.",
         "Remove the transfer and use an approved, auditable data-handling workflow."),
)

SEVERITY_SCORE = {"low": 1, "medium": 4, "high": 7, "critical": 10}
