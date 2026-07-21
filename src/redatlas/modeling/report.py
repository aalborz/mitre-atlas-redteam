from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass
class AttackPath:
    description: str
    technique_ids: list[str] = field(default_factory=list)


@dataclass
class TechniqueFinding:
    id: str
    name: str
    framework: str
    rationale: str


@dataclass
class ThreatModelReport:
    system_name: str
    summary: str
    attack_paths: list[AttackPath] = field(default_factory=list)
    applicable_techniques: list[TechniqueFinding] = field(default_factory=list)
    mitigations: list[str] = field(default_factory=list)
    detections: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    def to_markdown(self) -> str:
        lines = [f"# Threat Model: {self.system_name}", "", self.summary, ""]

        lines.append("## Likely Attack Paths")
        if self.attack_paths:
            for path in self.attack_paths:
                ids = ", ".join(path.technique_ids)
                lines.append(f"- {path.description} ({ids})")
        else:
            lines.append("_None identified._")
        lines.append("")

        lines.append("## Applicable Techniques")
        if self.applicable_techniques:
            lines.append("| ID | Name | Framework | Rationale |")
            lines.append("|---|---|---|---|")
            for finding in self.applicable_techniques:
                lines.append(
                    f"| {finding.id} | {finding.name} | {finding.framework} | {finding.rationale} |"
                )
        else:
            lines.append("_None identified._")
        lines.append("")

        lines.append("## Suggested Mitigations")
        if self.mitigations:
            lines.extend(f"- {m}" for m in self.mitigations)
        else:
            lines.append("_None identified._")
        lines.append("")

        lines.append("## Suggested Detections")
        if self.detections:
            lines.extend(f"- {d}" for d in self.detections)
        else:
            lines.append("_None identified._")
        lines.append("")

        return "\n".join(lines)
