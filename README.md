# 🛡️ SkillShield

Offline security scanner for AI agent skills, instruction files, and MCP configurations. SkillShield finds suspicious commands, prompt-injection language, secret collection, overbroad filesystem access, and approval bypasses before an agent executes them.

## Why SkillShield?

AI coding agents increasingly consume local instructions and connect to external tools. Those files are executable trust boundaries: a malicious or compromised instruction can request secrets, bypass confirmation, or execute remote code. SkillShield adds a fast, reviewable security check for repositories and CI pipelines.

## Install

```bash
git clone https://github.com/gesti444/skillshield.git
cd skillshield
python3 -m pip install .
```

It requires Python 3.10+ and has zero runtime dependencies.

## Usage

```bash
# Scan the current repository
skillshield .

# Scan one skill
skillshield path/to/SKILL.md

# Generate JSON or GitHub-compatible SARIF
skillshield . --format json -o skillshield.json
skillshield . --format sarif -o skillshield.sarif

# Never fail CI; report only
skillshield . --fail-on never
```

By default, the command exits with status `1` when high-risk findings are present, making it suitable for CI.

## What it detects

- Destructive shell commands
- Download-and-execute pipelines
- Credential and secret collection
- Prompt-injection override language
- Sensitive filesystem access
- Encoded executable content
- Overbroad MCP filesystem roots
- Automatic approval or confirmation bypass
- Suspicious transfer of local secrets

## Scope and limitations

SkillShield is a deterministic static analyzer. It does not execute instructions, access the network, or upload scanned content. Pattern matching can produce false positives and cannot prove that a skill is safe. Always review third-party agent instructions manually and run agents with least privilege.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## Contributing and sponsorship

New detection rules, safe fixtures, editor integrations, and documentation improvements are welcome. If SkillShield protects your workflow, support continued maintenance with the GitHub **Sponsor** button.

## License

[MIT](LICENSE)
