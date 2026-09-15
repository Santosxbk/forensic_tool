"""Testes de integração do fluxo principal com arquivos inertes."""

import json
import time
from pathlib import Path

from click.testing import CliRunner

from src.forensic_tool.analyzers import register_all_analyzers
from src.forensic_tool.analyzers.network_analyzer import NetworkAnalyzer
from src.forensic_tool.analyzers.security_analyzer import SecurityAnalyzer
from src.forensic_tool.cli.main import main
from src.forensic_tool.cli.reports import ReportGenerator
from src.forensic_tool.core import AnalysisManager, Config, ResultsDatabase


def test_cli_initialization():
    result = CliRunner().invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "analyze" in result.output


def test_all_analyzers_registered_once():
    first = register_all_analyzers()
    second = register_all_analyzers()
    assert {analyzer.name for analyzer in first.get_all_analyzers()} == {
        "ImageAnalyzer", "DocumentAnalyzer", "MediaAnalyzer", "NetworkAnalyzer", "SecurityAnalyzer"
    }
    assert len(first.get_all_analyzers()) == len(second.get_all_analyzers())


def test_manager_initialization(test_config, test_database):
    manager = AnalysisManager(test_config, test_database)
    assert manager.registry.get_all_analyzers()
    manager.shutdown()


def test_network_apache_log(tmp_path):
    log_path = tmp_path / "apache_access.log"
    log_path.write_text(
        '192.0.2.1 - - [15/Sep/2026:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 42\n',
        encoding="utf-8",
    )
    result = NetworkAnalyzer().analyze(log_path)
    assert result.success
    assert result.file_size == log_path.stat().st_size
    assert result.metadata["total_requests"] == 1
    assert result.analysis_duration >= 0


def test_security_analyzes_inert_binary(tmp_path):
    binary_path = tmp_path / "evidence.bin"
    binary_path.write_bytes(b"\x00\x01safe inert evidence\x02")
    result = SecurityAnalyzer().analyze(binary_path)
    assert result.success
    assert result.file_size == binary_path.stat().st_size
    assert "entropy_analysis" in result.metadata
    json.dumps(result.to_dict())


def test_complete_session_and_reports(tmp_path, test_config):
    (tmp_path / "sample.txt").write_text("synthetic evidence", encoding="utf-8")
    (tmp_path / "apache_access.log").write_text(
        '198.51.100.2 - - [15/Sep/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 12\n',
        encoding="utf-8",
    )
    (tmp_path / "evidence.bin").write_bytes(b"\x00\x01\x02")
    test_config.database.path = tmp_path / "results.db"
    manager = AnalysisManager(test_config, ResultsDatabase(test_config.database.path))
    try:
        assert manager.start_analysis("integration", str(tmp_path))
        for _ in range(100):
            session = manager.get_analysis_session("integration")
            if session and session.status != "running":
                break
            time.sleep(0.02)
        session = manager.get_analysis_session("integration")
        assert session.status == "completed"
        assert session.processed_files == session.total_files == 3
        results = manager.get_analysis_results("integration", limit=10)
        assert len(results) == 3
        assert all("metadata" in result and "file_size" in result for result in results)

        output_dir = tmp_path / "reports"
        generated = ReportGenerator(manager).generate_reports(
            "integration", output_dir, ["json", "csv", "excel", "html"]
        )
        assert {path.suffix for path in generated} == {".json", ".csv", ".xlsx", ".html"}
        assert all(path.stat().st_size > 0 for path in generated)
    finally:
        manager.shutdown()
