# mitre-atlas-redteam

A red-teaming / threat-modeling CLI that maps systems and architectures to the
[MITRE ATT&CK](https://attack.mitre.org/) (traditional IT/OT attacker techniques) and
[MITRE ATLAS](https://atlas.mitre.org/) (AI/ML system attacker techniques) knowledge bases.

This is the **MVP**: a shared ATT&CK + ATLAS data layer, a threat-modeling report
generator, and an interactive chat advisor for tabletop exercises. See
[Roadmap](#roadmap) for what's next.

## Status: analysis & reporting only

This tool does not execute any attack techniques. It maps systems to known
techniques, generates reports, and answers questions grounded in the official
ATT&CK/ATLAS data. There is no capability in this MVP to run exploits or
touch a target system.

## Install

Requires Python 3.11+.

```bash
pip install -e ".[dev]"
```

## Configuration

The threat-modeling and chat-advisor commands call the Anthropic Claude API and
need an API key:

```bash
export ANTHROPIC_API_KEY="your-key-here"   # bash
$env:ANTHROPIC_API_KEY = "your-key-here"   # PowerShell
```

Get a key at https://console.anthropic.com/. The `redatlas data` commands work
without a key — they only read the local ATT&CK/ATLAS data.

Optional: `ANTHROPIC_MODEL` to override the default model, `REDATLAS_CACHE_DIR`
to override where downloaded ATT&CK/ATLAS data is cached.

## Usage

```bash
# Download and cache ATT&CK (enterprise) + ATLAS data (first run only; re-run with --refresh to update)
redatlas data fetch

# Search techniques across both frameworks
redatlas data search "prompt injection"

# Show details for a specific technique
redatlas data show T1566

# Generate a threat model report from a system description
redatlas model generate my-system.yaml --output report
# writes report.md and report.json

# Start an interactive, ATT&CK/ATLAS-grounded chat advisor
redatlas chat start
```

See [tests/fixtures/sample_system.yaml](tests/fixtures/sample_system.yaml) for
an example system description you can adapt for `model generate`.

## Development

```bash
pip install -e ".[dev]"
ruff check .
ruff format --check .
pytest --cov=redatlas
```

All tests run against local fixtures — no network access or API key required.

## Roadmap

Not yet implemented, but the data layer (`redatlas/data/`) is designed so
neither of these require reworking it:

- **Coverage/gap dashboard** — an ATT&CK Navigator-style heatmap comparing your
  detections/controls against the full technique corpus.
- **Execution hooks** — Atomic Red Team / Caldera integration to actually run
  techniques in a lab. This will be gated behind a mandatory authorization
  guardrail (a signed scope config naming the engagement and an explicit
  allow-list of targets, checked before every execution, with audit logging)
  before any execution code lands. See `src/redatlas/exec/__init__.py` for the
  planned design.

## Responsible use

This tool is intended for authorized security testing, red-team engagements,
and defensive threat modeling. Only use it against systems you own or are
explicitly authorized to assess.
