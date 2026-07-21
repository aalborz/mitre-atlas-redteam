from __future__ import annotations

import json

from redatlas.data.schema import Framework
from redatlas.data.store import DataStore

CHAT_TOOLS = [
    {
        "name": "search_techniques",
        "description": (
            "Search MITRE ATT&CK and ATLAS techniques by keyword. Call this before "
            "answering any question that names or implies specific techniques."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "framework": {"type": "string", "enum": ["attack", "atlas", "any"]},
                "top_k": {"type": "integer"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "get_technique",
        "description": "Get full details for a technique by its exact ATT&CK/ATLAS ID.",
        "input_schema": {
            "type": "object",
            "properties": {"technique_id": {"type": "string"}},
            "required": ["technique_id"],
        },
    },
    {
        "name": "get_mitigations",
        "description": "Get mitigations mapped to a technique ID.",
        "input_schema": {
            "type": "object",
            "properties": {"technique_id": {"type": "string"}},
            "required": ["technique_id"],
        },
    },
]


def _framework_arg(value: str | None) -> Framework | None:
    if not value or value == "any":
        return None
    return Framework(value)


def dispatch(store: DataStore, name: str, tool_input: dict) -> str:
    if name == "search_techniques":
        results = store.search(
            tool_input["query"],
            framework=_framework_arg(tool_input.get("framework")),
            limit=tool_input.get("top_k", 10),
        )
        return json.dumps(
            [{"id": t.id, "name": t.name, "framework": t.framework.value} for t in results]
        )

    if name == "get_technique":
        technique = store.get_technique(tool_input["technique_id"])
        if not technique:
            return json.dumps({"error": f"Unknown technique id {tool_input['technique_id']!r}"})
        return json.dumps(
            {
                "id": technique.id,
                "name": technique.name,
                "description": technique.description,
                "framework": technique.framework.value,
                "tactic_ids": list(technique.tactic_ids),
                "platforms": list(technique.platforms),
                "mitigation_ids": list(technique.mitigation_ids),
            }
        )

    if name == "get_mitigations":
        mitigations = store.get_mitigations_for(tool_input["technique_id"])
        return json.dumps(
            [{"id": m.id, "name": m.name, "description": m.description} for m in mitigations]
        )

    return json.dumps({"error": f"Unknown tool {name!r}"})
