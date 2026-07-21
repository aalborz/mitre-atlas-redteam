# mitre-atlas-redteam

A red-teaming / threat-modeling CLI that maps systems and architectures to the
[MITRE ATT&CK](https://attack.mitre.org/) (traditional IT/OT attacker techniques) and
[MITRE ATLAS](https://atlas.mitre.org/) (AI/ML system attacker techniques) knowledge bases.

Four pieces: a shared ATT&CK + ATLAS data layer, a threat-modeling report
generator, an interactive chat advisor for tabletop exercises, a coverage/gap
dashboard, and gated execution hooks for validating techniques locally via
Atomic Red Team. See [Roadmap](#roadmap) for what's still open.

## Status: execution capability exists, and is gated

Most of this tool (`data`, `model`, `chat`, `coverage`) is analysis and
reporting only — it never touches a target system. `redatlas exec run` is the
one exception: it can actually execute an Atomic Red Team test locally. It
refuses to run anything unless a local, human-authored `authorization.yaml`
names the engagement, an active time window, and an allow-listed target — see
[Execution hooks](#execution-hooks-redatlas-exec) below. Every attempt, allowed
or refused, is audit-logged.

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
to override where downloaded ATT&CK/ATLAS data (and the exec audit log) is cached.

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

# Generate a Navigator layer of covered vs. gap techniques
redatlas coverage report my-covered-techniques.yaml --domain enterprise --output coverage-layer.json
# upload coverage-layer.json to https://mitre-attack.github.io/attack-navigator/
```

See [tests/fixtures/sample_system.yaml](tests/fixtures/sample_system.yaml) for
an example system description, and
[tests/fixtures/covered_techniques.yaml](tests/fixtures/covered_techniques.yaml)
for the coverage input format (`covered: [T1566, ...]`).

## Execution hooks (`redatlas exec`)

`redatlas exec run <TECHNIQUE_ID>` runs (or dry-runs) an
[Atomic Red Team](https://github.com/redcanaryco/invoke-atomicredteam) test for
a technique. It is gated end-to-end:

1. **Authorization file.** Copy [authorization.example.yaml](authorization.example.yaml)
   to `authorization.yaml` (gitignored — never commit a real one) and fill in
   your engagement name, an active time window, and an allow-listed set of
   targets. Missing, malformed, expired, or off-allow-list — execution is
   refused before anything else happens.
2. **Dry run by default.** Without `--execute`, the command only validates
   authorization and reports what would run; PowerShell is never invoked.
3. **Audit log.** Every attempt — allowed or refused, dry run or real — is
   appended as a JSON line to the cache dir's `exec-audit.log`.
4. **Local only.** Only `--target localhost` is supported for `--execute` in
   this version; remote execution isn't implemented.
5. **Requires Invoke-AtomicRedTeam.** If it's not installed, `--execute` fails
   with install instructions rather than silently doing nothing.

```bash
redatlas exec run T1059                          # dry run: validate authorization only
redatlas exec run T1059 --execute                # actually run it, locally
redatlas exec run T1059 --execute --test-number 1 --cleanup
```

## Development

```bash
pip install -e ".[dev]"
ruff check .
ruff format --check .
pytest --cov=redatlas
```

All tests run against local fixtures — no network access, API key, or real
PowerShell/Atomic Red Team install required.

## Roadmap

- **Caldera integration** as a second execution backend alongside Atomic Red
  Team, behind the same authorization/audit layers.
- **Remote execution** (e.g. via a PSSession) for `redatlas exec run` — local
  only for now.
- **Sigma-rule / Navigator-layer import** for `redatlas coverage report`, as
  alternatives to the current plain YAML list of covered technique IDs.

## Responsible use

This tool is intended for authorized security testing, red-team engagements,
and defensive threat modeling. Only use `redatlas exec run --execute` against
systems you own or are explicitly authorized to test, and only after filling
in a real `authorization.yaml` — the tool enforces this, but it is not a
substitute for whatever formal authorization process (e.g. a signed
rules-of-engagement document) your organization or client already requires.
