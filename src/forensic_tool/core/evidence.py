"""Modelos e operações de integridade para casos e evidências."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

from .database import ResultsDatabase


def utc_now() -> datetime:
    """Retorna um timestamp UTC com timezone explícito."""
    return datetime.now(timezone.utc)


def calculate_file_hashes(path: Path, algorithms: Tuple[str, ...] = ("sha256", "md5")) -> Dict[str, str]:
    """Calcula hashes em modo somente leitura e em chunks."""
    hashers = {algorithm: hashlib.new(algorithm) for algorithm in algorithms}
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            for hasher in hashers.values():
                hasher.update(chunk)
    return {algorithm: hasher.hexdigest() for algorithm, hasher in hashers.items()}


@dataclass(frozen=True)
class CaseRecord:
    case_id: str
    name: str
    created_at: str
    status: str = "open"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "name": self.name,
            "created_at": self.created_at,
            "status": self.status,
        }


@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    case_id: str
    source_name: str
    source_path: str
    relative_path: Optional[str]
    file_size: int
    sha256: str
    additional_hashes: Dict[str, str]
    acquired_at: str
    operator: str
    acquisition_reason: str
    status: str = "registered"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "case_id": self.case_id,
            "source_name": self.source_name,
            "source_path": self.source_path,
            "relative_path": self.relative_path,
            "file_size": self.file_size,
            "sha256": self.sha256,
            "additional_hashes": dict(self.additional_hashes),
            "acquired_at": self.acquired_at,
            "operator": self.operator,
            "acquisition_reason": self.acquisition_reason,
            "status": self.status,
        }


@dataclass(frozen=True)
class CustodyEvent:
    event_id: str
    evidence_id: str
    sequence: int
    event_type: str
    actor: str
    timestamp: str
    description: str
    details: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "evidence_id": self.evidence_id,
            "sequence": self.sequence,
            "event_type": self.event_type,
            "actor": self.actor,
            "timestamp": self.timestamp,
            "description": self.description,
            "details": dict(self.details),
        }


class EvidenceService:
    """Registra evidências e mantém eventos de cadeia de custódia append-only."""

    def __init__(self, database: ResultsDatabase, operator: str = "unknown"):
        self.database = database
        self.operator = operator

    def create_case(self, name: str) -> CaseRecord:
        if not name.strip():
            raise ValueError("O nome do caso não pode ser vazio")
        case = CaseRecord(str(uuid4()), name.strip(), utc_now().isoformat())
        if not self.database.create_case(case.to_dict()):
            raise RuntimeError("Não foi possível criar o caso")
        return case

    def list_cases(self) -> List[Dict[str, Any]]:
        return self.database.list_cases()

    def register(self, path: Path, case_id: str, reason: str = "triagem", operator: Optional[str] = None) -> EvidenceRecord:
        if not self.database.case_exists(case_id):
            raise KeyError(f"Caso não encontrado: {case_id}")
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Evidência não encontrada: {path}")
        if not path.is_file():
            raise ValueError("A evidência deve ser um arquivo regular")
        if path.is_symlink():
            raise ValueError("Links simbólicos não podem ser registrados como evidência")
        stat_result = path.stat()
        hashes = calculate_file_hashes(path)
        evidence = EvidenceRecord(
            evidence_id=str(uuid4()),
            case_id=case_id,
            source_name=path.name,
            source_path=str(path.resolve()),
            relative_path=None,
            file_size=stat_result.st_size,
            sha256=hashes["sha256"],
            additional_hashes={key: value for key, value in hashes.items() if key != "sha256"},
            acquired_at=utc_now().isoformat(),
            operator=operator or self.operator,
            acquisition_reason=reason,
        )
        if not self.database.create_evidence(evidence.to_dict()):
            raise RuntimeError("Não foi possível registrar a evidência")
        self.database.append_custody_event(
            evidence.evidence_id,
            "registered",
            evidence.operator,
            "Evidência registrada com hash de entrada",
            {"sha256": evidence.sha256, "file_size": evidence.file_size},
        )
        return evidence

    def verify(self, evidence_id: str) -> Dict[str, Any]:
        evidence = self.database.get_evidence(evidence_id)
        if evidence is None:
            raise KeyError(f"Evidência não encontrada: {evidence_id}")
        path = Path(evidence["source_path"])
        if not path.exists() or not path.is_file():
            result = {"evidence_id": evidence_id, "matches": False, "reason": "arquivo ausente"}
        else:
            current_hash = calculate_file_hashes(path, ("sha256",))["sha256"]
            result = {
                "evidence_id": evidence_id,
                "registered_sha256": evidence["sha256"],
                "current_sha256": current_hash,
                "matches": current_hash == evidence["sha256"],
            }
        self.database.append_custody_event(
            evidence_id,
            "verified",
            self.operator,
            "Hash da evidência verificado",
            result,
        )
        return result

    def history(self, evidence_id: str) -> List[Dict[str, Any]]:
        if self.database.get_evidence(evidence_id) is None:
            raise KeyError(f"Evidência não encontrada: {evidence_id}")
        return self.database.get_custody_events(evidence_id)
