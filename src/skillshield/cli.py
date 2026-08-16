from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .output import render_json, render_sarif, render_text
from .scanner import scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Scan AI agent skills and MCP configurations for risky instructions.")
    parser.add_argument("target", nargs="?", default=".", help="File or directory to scan (default: current directory)")
    parser.add_argument("-f", "--format", choices=("text", "json", "sarif"), default="text")
    parser.add_argument("-o", "--output", help="Write results to a file")
    parser.add_argument("--fail-on", choices=("never", "medium", "high", "critical"), default="high")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = scan(args.target)
        renderers = {"text": render_text, "json": render_json, "sarif": render_sarif}
        content = renderers[args.format](report)
        if args.output:
            Path(args.output).write_text(content, encoding="utf-8")
        else:
            print(content, end="")
        thresholds = {"never": 101, "medium": 4, "high": 7, "critical": 10}
        return 1 if report["risk_score"] >= thresholds[args.fail_on] else 0
    except OSError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
