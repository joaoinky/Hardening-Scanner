"""Contrato público compartilhado pelos módulos e pelos relatórios."""

from dataclasses import asdict, dataclass, field
from typing import Any

STATUSES = ("pass", "fail", "warning")
SEVERITIES = ("critical", "high", "medium", "low", "info")


@dataclass(frozen=True)
class Result:
    id: str
    name: str
    status: str
    severity: str
    description: str
    recommendation: str
    evidence: dict[str, Any] = field(default_factory=dict)
    reason: str | None = None

    def __post_init__(self):
        if self.status not in STATUSES or self.severity not in SEVERITIES:
            raise ValueError("Status ou severidade inválidos")
        if not self.id or not self.name:
            raise ValueError("ID e nome são obrigatórios")
        if self.status == "warning" and not self.reason:
            raise ValueError("Warnings devem explicar a limitação ou revisão necessária")

    def to_dict(self):
        return asdict(self)


def inconclusive(check_id, name, reason, severity="medium", recommendation=None):
    return Result(
        check_id, name, "warning", severity,
        "Verificação inconclusiva ou dependente de revisão contextual.",
        recommendation or "Revise a evidência e execute novamente com os pré-requisitos disponíveis.",
        reason=reason,
    )
