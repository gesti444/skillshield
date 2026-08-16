from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path

from .rules import RULES, SEVERITY_SCORE


DEFAULT_NAMES = {"skill.md", "agents.md", "claude.md", "mcp.json", ".mcp.json"}
DEFAULT_SUFFIXES = {".md", ".json", ".yaml", ".yml", ".toml"}
MAX_FILE_SIZE = 2 * 1024 * 1024


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    path: str
    line: int
    column: int
    excerpt: str
    description: str
    recommendation: str

    def to_dict(self) -> dict:
        return asdict(self)


def candidate_files(target: Path) -> list[Path]:
    if target.is_file():
        return [target]
    files = []
    for path in target.rglob("*"):
        if any(part in {".git", ".venv", "node_modules", "dist", "build"} for part in path.parts):
            continue
        if path.is_file() and (path.name.lower() in DEFAULT_NAMES or path.suffix.lower() in DEFAULT_SUFFIXES):
            files.append(path)
    return sorted(files)


def scan_file(path: Path, display_path: str | None = None) -> list[Finding]:
    if path.stat().st_size > MAX_FILE_SIZE:
        return []
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return []
    findings = []
    label = display_path or str(path)
    for rule in RULES:
        for match in rule.pattern.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            last_newline = text.rfind("\n", 0, match.start())
            column = match.start() - last_newline
            excerpt = text.splitlines()[line - 1].strip()[:240]
            findings.append(Finding(rule.id, rule.title, rule.severity, label, line, column, excerpt, rule.description, rule.recommendation))
    return findings


def scan(target: str | Path) -> dict:
    root = Path(target).resolve()
    if not root.exists():
        raise FileNotFoundError(f"Target does not exist: {target}")
    files = candidate_files(root)
    findings = []
    for path in files:
        label = path.name if root.is_file() else str(path.relative_to(root))
        findings.extend(scan_file(path, label))
    findings.sort(key=lambda item: (-SEVERITY_SCORE[item.severity], item.path, item.line))
    risk = min(100, sum(SEVERITY_SCORE[item.severity] for item in findings))
    return {
        "tool": "SkillShield",
        "version": "0.1.0",
        "target": str(target),
        "files_scanned": len(files),
        "risk_score": risk,
        "findings": [item.to_dict() for item in findings],
        "summary": {severity: sum(item.severity == severity for item in findings) for severity in ("critical", "high", "medium", "low")},
    }
