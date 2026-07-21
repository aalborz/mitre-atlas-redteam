from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field


class Component(BaseModel):
    name: str
    description: str = ""
    technologies: list[str] = Field(default_factory=list)
    internet_facing: bool = False


class DataFlow(BaseModel):
    source: str
    destination: str
    description: str = ""
    sensitive: bool = False


class AIComponent(BaseModel):
    name: str
    description: str = ""
    model_type: str | None = None


class SystemModel(BaseModel):
    name: str
    description: str = ""
    components: list[Component] = Field(default_factory=list)
    data_flows: list[DataFlow] = Field(default_factory=list)
    trust_boundaries: list[str] = Field(default_factory=list)
    ai_ml_components: list[AIComponent] = Field(default_factory=list)
    notes: str = ""

    def to_search_text(self) -> str:
        parts = [self.name, self.description, self.notes]
        for c in self.components:
            parts.append(f"{c.name} {c.description} {' '.join(c.technologies)}")
        for f in self.data_flows:
            parts.append(f"{f.source} {f.destination} {f.description}")
        for ai in self.ai_ml_components:
            parts.append(f"{ai.name} {ai.description} {ai.model_type or ''}")
        parts.extend(self.trust_boundaries)
        return " ".join(p for p in parts if p)


def load_system_model(path: Path) -> SystemModel:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    return SystemModel.model_validate(raw)
