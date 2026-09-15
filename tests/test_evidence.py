"""Testes de integridade e cadeia de custódia com arquivos sintéticos."""

import hashlib
import json
from pathlib import Path

from click.testing import CliRunner

from src.forensic_tool.cli.main import main
from src.forensic_tool.core import EvidenceService, ResultsDatabase


def test_register_and_verify_evidence_without_modifying_original(tmp_path):
    database = ResultsDatabase(tmp_path / "evidence.db")
    source = tmp_path / "sample.txt"
    source.write_text("evidence content", encoding="utf-8")
    original_bytes = source.read_bytes()
    try:
        service = EvidenceService(database, operator="tester")
        case = service.create_case("Case A")
        evidence = service.register(source, case.case_id, reason="test acquisition")

        assert evidence.file_size == len(original_bytes)
        assert evidence.sha256 == hashlib.sha256(original_bytes).hexdigest()
        assert source.read_bytes() == original_bytes

        verification = service.verify(evidence.evidence_id)
        assert verification["matches"] is True
        history = service.history(evidence.evidence_id)
        assert [event["sequence"] for event in history] == [1, 2]
        assert [event["event_type"] for event in history] == ["registered", "verified"]
        json.dumps(history)
    finally:
        database.close()


def test_verify_detects_tampering(tmp_path):
    database = ResultsDatabase(tmp_path / "evidence.db")
    source = tmp_path / "sample.bin"
    source.write_bytes(b"original")
    try:
        service = EvidenceService(database)
        case = service.create_case("Case B")
        evidence = service.register(source, case.case_id)
        source.write_bytes(b"changed")
        verification = service.verify(evidence.evidence_id)
        assert verification["matches"] is False
        assert verification["registered_sha256"] != verification["current_sha256"]
    finally:
        database.close()


def test_evidence_cli_commands(tmp_path, monkeypatch):
    database_path = tmp_path / "cli.db"
    source = tmp_path / "sample.txt"
    source.write_text("cli evidence", encoding="utf-8")
    monkeypatch.setenv("FORENSIC_DB_PATH", str(database_path))
    runner = CliRunner()

    created = runner.invoke(main, ["case", "create", "CLI Case"])
    assert created.exit_code == 0, created.output
    case_id = json.loads(created.output)["case_id"]

    registered = runner.invoke(main, ["evidence", "register", str(source), "--case", case_id])
    assert registered.exit_code == 0, registered.output
    evidence_id = json.loads(registered.output)["evidence_id"]

    verified = runner.invoke(main, ["evidence", "verify", evidence_id])
    assert verified.exit_code == 0, verified.output
    assert json.loads(verified.output)["matches"] is True

    history = runner.invoke(main, ["evidence", "history", evidence_id])
    assert history.exit_code == 0, history.output
    assert len(json.loads(history.output)) == 2
