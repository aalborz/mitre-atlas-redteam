from __future__ import annotations

import json

from redatlas.config import get_default_model
from redatlas.data.store import DataStore
from redatlas.llm.client import get_client
from redatlas.modeling.inputs import SystemModel
from redatlas.modeling.report import AttackPath, TechniqueFinding, ThreatModelReport
from redatlas.modeling.retrieval import build_corpus, retrieve_relevant

THREAT_MODEL_SYSTEM_PROMPT = """\
You are a red-team threat-modeling assistant. You are given a description of a \
system and a list of candidate MITRE ATT&CK / MITRE ATLAS techniques retrieved \
from the official knowledge bases as context.

Rules:
- Only cite technique IDs that appear in the supplied context block. Never invent \
or recall a technique ID from memory.
- If you believe a relevant technique is missing from the context, describe it in \
prose without inventing an ID, and note that it should be verified against the \
official framework.
- Be concrete: tie each finding back to specific components or data flows named in \
the system description.
- Output must conform exactly to the provided JSON schema.
"""

REPORT_JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "attack_paths": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "description": {"type": "string"},
                    "technique_ids": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["description", "technique_ids"],
                "additionalProperties": False,
            },
        },
        "applicable_techniques": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "name": {"type": "string"},
                    "framework": {"type": "string"},
                    "rationale": {"type": "string"},
                },
                "required": ["id", "name", "framework", "rationale"],
                "additionalProperties": False,
            },
        },
        "mitigations": {"type": "array", "items": {"type": "string"}},
        "detections": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["summary", "attack_paths", "applicable_techniques", "mitigations", "detections"],
    "additionalProperties": False,
}


def _render_technique_context(techniques) -> str:
    lines = []
    for t in techniques:
        lines.append(f"- [{t.framework.value}] {t.id} — {t.name}: {t.description[:400]}")
    return "\n".join(lines)


def _render_user_prompt(system: SystemModel, context_block: str) -> str:
    return (
        f"System name: {system.name}\n"
        f"Description: {system.description}\n"
        f"Components: {[c.model_dump() for c in system.components]}\n"
        f"Data flows: {[f.model_dump() for f in system.data_flows]}\n"
        f"Trust boundaries: {system.trust_boundaries}\n"
        f"AI/ML components: {[a.model_dump() for a in system.ai_ml_components]}\n"
        f"Notes: {system.notes}\n\n"
        f"Candidate techniques (only cite IDs from this list):\n{context_block}\n\n"
        "Produce a threat model report as JSON matching the provided schema."
    )


def generate_report(
    system: SystemModel,
    store: DataStore,
    *,
    model: str | None = None,
    top_k: int = 25,
) -> ThreatModelReport:
    include_atlas = bool(system.ai_ml_components)
    corpus = build_corpus(store, include_atlas=include_atlas)
    candidates = retrieve_relevant(system, corpus, top_k=top_k)
    context_block = _render_technique_context(candidates)

    client = get_client()
    response = client.messages.create(
        model=model or get_default_model(),
        max_tokens=8000,
        system=THREAT_MODEL_SYSTEM_PROMPT,
        output_config={"format": {"type": "json_schema", "schema": REPORT_JSON_SCHEMA}},
        messages=[{"role": "user", "content": _render_user_prompt(system, context_block)}],
    )

    text = next(block.text for block in response.content if block.type == "text")
    data = json.loads(text)

    return ThreatModelReport(
        system_name=system.name,
        summary=data["summary"],
        attack_paths=[AttackPath(**p) for p in data["attack_paths"]],
        applicable_techniques=[TechniqueFinding(**f) for f in data["applicable_techniques"]],
        mitigations=data["mitigations"],
        detections=data["detections"],
    )
