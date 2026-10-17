from __future__ import annotations

from dataclasses import dataclass

from redatlas.chat.tools import CHAT_TOOLS, dispatch
from redatlas.config import get_default_model
from redatlas.data.store import DataStore
from redatlas.llm.client import get_client

ADVISOR_SYSTEM_PROMPT = """\
You are a red-team advisor for tabletop exercises, grounded in the MITRE ATT&CK \
and MITRE ATLAS knowledge bases via tools.

Rules:
- Ground every technique ID you mention by calling search_techniques or \
get_technique first; never state a technique ID you have not retrieved via a \
tool call in this conversation.
- Prefer ATLAS techniques when the discussion involves AI/ML systems, models, or \
data pipelines; prefer ATT&CK otherwise.
- Be concise and practical, as if advising a red team during a live exercise.
"""

# History cap, in user questions. Once the conversation exceeds MAX_EXCHANGES,
# the oldest questions (and their tool calls/answers) are dropped until
# KEEP_EXCHANGES remain. Trimming in one big step rather than one question per
# turn means the cached prefix is only rebuilt occasionally, not every turn.
MAX_EXCHANGES = 12
KEEP_EXCHANGES = 6


@dataclass
class TokenUsage:
    input: int = 0
    cache_read: int = 0
    cache_write: int = 0
    output: int = 0
    calls: int = 0

    def add(self, usage) -> None:
        self.calls += 1
        if usage is None:
            return
        self.input += getattr(usage, "input_tokens", 0) or 0
        self.cache_read += getattr(usage, "cache_read_input_tokens", 0) or 0
        self.cache_write += getattr(usage, "cache_creation_input_tokens", 0) or 0
        self.output += getattr(usage, "output_tokens", 0) or 0

    def merge(self, other: TokenUsage) -> None:
        self.input += other.input
        self.cache_read += other.cache_read
        self.cache_write += other.cache_write
        self.output += other.output
        self.calls += other.calls

    def format(self, label: str) -> str:
        return (
            f"[{label}] {self.calls} API call(s) | input {self.input:,} | "
            f"cache read {self.cache_read:,} | cache write {self.cache_write:,} | "
            f"output {self.output:,}"
        )


def _is_new_question(message: dict) -> bool:
    """True for a user turn the person typed (not a tool_result turn)."""
    return message["role"] == "user" and isinstance(message["content"], str)


def trim_history(
    messages: list[dict],
    *,
    max_exchanges: int = MAX_EXCHANGES,
    keep_exchanges: int = KEEP_EXCHANGES,
) -> list[dict]:
    """Drop whole old exchanges so history always starts at a typed question.

    Cutting only at question boundaries keeps every tool_use paired with its
    tool_result, which the API requires.
    """
    starts = [i for i, m in enumerate(messages) if _is_new_question(m)]
    if len(starts) <= max_exchanges:
        return messages
    return messages[starts[-keep_exchanges] :]


def _print_text_blocks(content) -> None:
    for block in content:
        if block.type == "text" and block.text:
            print(f"assistant> {block.text}")


def run_repl(store: DataStore, *, model: str | None = None) -> None:
    client = get_client()
    resolved_model = model or get_default_model()
    messages: list[dict] = []
    session_usage = TokenUsage()

    print("redatlas chat advisor. Type 'exit' or 'quit' to leave.")
    while True:
        try:
            user_input = input("you> ")
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if user_input.strip().lower() in {"exit", "quit"}:
            break
        if not user_input.strip():
            continue

        messages = trim_history(messages + [{"role": "user", "content": user_input}])
        turn_start = len(messages) - 1
        turn_usage = TokenUsage()

        while True:
            response = client.messages.create(
                model=resolved_model,
                # Room for adaptive thinking, which counts toward max_tokens.
                max_tokens=4000,
                tools=CHAT_TOOLS,
                system=ADVISOR_SYSTEM_PROMPT,
                # Automatic caching: marks the last block of the request, so each
                # call reads the whole prior conversation from cache instead of
                # paying full price to resend it.
                cache_control={"type": "ephemeral"},
                messages=messages,
            )
            turn_usage.add(getattr(response, "usage", None))

            if response.stop_reason == "refusal":
                # Drop the declined question so it doesn't follow later turns.
                messages = messages[:turn_start]
                print(
                    "assistant> [The model declined this request. Try rephrasing it, "
                    "or rerun with --model claude-sonnet-5-5.]"
                )
                break

            messages.append({"role": "assistant", "content": response.content})

            if response.stop_reason != "tool_use":
                _print_text_blocks(response.content)
                break

            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    result = dispatch(store, block.name, block.input)
                    tool_results.append(
                        {"type": "tool_result", "tool_use_id": block.id, "content": result}
                    )
            messages.append({"role": "user", "content": tool_results})

        session_usage.merge(turn_usage)
        print(turn_usage.format("tokens this turn"))

    if session_usage.calls:
        print(session_usage.format("tokens this session"))
