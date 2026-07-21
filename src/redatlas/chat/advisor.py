from __future__ import annotations

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


def _print_text_blocks(content) -> None:
    for block in content:
        if block.type == "text" and block.text:
            print(f"assistant> {block.text}")


def run_repl(store: DataStore, *, model: str | None = None) -> None:
    client = get_client()
    resolved_model = model or get_default_model()
    messages: list[dict] = []

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

        messages.append({"role": "user", "content": user_input})

        while True:
            response = client.messages.create(
                model=resolved_model,
                max_tokens=2000,
                tools=CHAT_TOOLS,
                system=[
                    {
                        "type": "text",
                        "text": ADVISOR_SYSTEM_PROMPT,
                        "cache_control": {"type": "ephemeral"},
                    }
                ],
                messages=messages,
            )
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
