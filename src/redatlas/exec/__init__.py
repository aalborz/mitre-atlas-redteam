"""Execution hooks (Atomic Red Team / Caldera integration) -- NOT implemented in the MVP.

This package is a landing spot for a future feature: actually triggering ATT&CK/
ATLAS technique execution in a lab environment via existing frameworks (Atomic Red
Team, Caldera). Before any execution capability is implemented here, it must be
gated behind an explicit authorization guardrail, at minimum:

  - A local, human-authored scope file (e.g. `authorization.yaml`) naming the
    engagement, its time window, and an explicit allow-list of target
    hosts/IPs/ranges.
  - A runtime check, before every single technique execution, that the intended
    target is present in that allow-list -- refuse otherwise.
  - Audit logging of every execution attempt (allowed or refused).

No CLI command is wired to this package yet.
"""

from __future__ import annotations


def run_technique(*args, **kwargs) -> None:
    raise NotImplementedError(
        "Execution hooks are not implemented in the MVP. See redatlas.exec "
        "module docstring for the planned authorization-guardrail design."
    )
