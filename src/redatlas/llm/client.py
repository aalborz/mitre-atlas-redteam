from __future__ import annotations

import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import anthropic


class MissingAPIKeyError(RuntimeError):
    def __init__(self) -> None:
        super().__init__(
            "ANTHROPIC_API_KEY is not set. This command needs Claude API access.\n"
            "Set it with:\n"
            "  PowerShell:  $env:ANTHROPIC_API_KEY = 'your-key-here'\n"
            "  bash:        export ANTHROPIC_API_KEY='your-key-here'\n"
            "Get a key at https://console.anthropic.com/"
        )


def get_client() -> anthropic.Anthropic:
    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise MissingAPIKeyError()

    import anthropic

    return anthropic.Anthropic()
