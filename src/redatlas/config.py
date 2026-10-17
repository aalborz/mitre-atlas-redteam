import os

DEFAULT_MODEL = "claude-haiku-5-5"


def get_default_model() -> str:
    return os.environ.get("ANTHROPIC_MODEL", DEFAULT_MODEL)
