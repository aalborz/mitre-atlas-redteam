"""Execution hooks: Atomic Red Team integration, gated by an authorization guardrail.

Every execution attempt -- allowed or refused -- goes through, in order:

  1. `redatlas.exec.authorization.load_authorization` / `check_authorized` --
     refuses to proceed unless a local, human-authored authorization file
     names the engagement, a still-open time window, and an allow-listed
     target. See authorization.example.yaml at the repo root for the schema.
  2. `redatlas.exec.audit.log_attempt` -- appends a JSON-line audit entry for
     every attempt, whether it was allowed or refused.
  3. `redatlas.exec.atomic_red_team.run_technique` -- the actual execution
     backend. Defaults to a dry run (`execute=False`): authorization is
     checked and logged, but PowerShell is never invoked. Only remote target
     `localhost` is supported; remote execution (e.g. via a PSSession) is not
     implemented yet.

Caldera integration is not implemented; `run_technique`'s signature is kept
narrow enough that a second backend could be added alongside
`atomic_red_team.py` later without changing the authorization/audit layers.
"""

from __future__ import annotations
