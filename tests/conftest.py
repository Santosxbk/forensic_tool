"""
Configurações e fixtures para testes do Forensic Tool
"""

import pytest
import tempfile
import shutil
from pathlib import Path
from typing import Generator
import sqlite3
import json
from datetime import datetime

from src.forensic_tool.core import Config, ResultsDatabase, AnalysisManager
from src.forensic_tool.utils import setup_logger


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Cria um diretório temporário para testes"""
    temp_path = Path(tempfile.mkdtemp())
    try:
        yield temp_path
    finally:
        shutil.rmtree(temp_path, ignore_errors=True)


@pytest.fixture
def test_config(temp_dir: Path) -> Config:
    """Cria uma configuração de teste"""
    config = Config()
    
    # Configurações específicas para testes
    config.database.path = temp_dir / "test_forensic.db"
    config.logging.file_path = temp_dir / "test_forensic.log"
    config.logging.level = "DEBUG"
    config.analysis.thread_count = 2  # Reduzido para testes
    config.analysis.max_files_per_analysis = 100
    config.analysis.max_file_size_mb = 10
    
    return config


@pytest.fixture
def test_database(test_config: Config) -> Generator[ResultsDatabase, None, None]:
    """Cria um banco de dados de teste"""
    db = ResultsDatabase(test_config.database.path)
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def analysis_manager(test_config: Config, test_database: ResultsDatabase) -> Generator[AnalysisManager, None, None]:
    """Cria um gerenciador de análises para testes"""
    manager = AnalysisManager(test_config, test_database)
    try:
        yield manager
    finally:
        manager.shutdown()


@pytest.fixture
def sample_files(temp_dir: Path) -> Path:
    """Cria arquivos de exemplo para testes"""
    samples_dir = temp_dir / "samples"
    samples_dir.mkdir()
    
    # Arquivo de texto simples
    (samples_dir / "test.txt").write_text("Este é um arquivo de teste", encoding='utf-8')
    
    # Arquivo JSON
    json_data = {"name": "test", "value": 123, "timestamp": datetime.now().isoformat()}
    (samples_dir / "test.json").write_text(json.dumps(json_data), encoding='utf-8')
    
    # Arquivo CSV
    csv_content = "nome,idade,cidade\nJoão,30,São Paulo\nMaria,25,Rio de Janeiro"
    (samples_dir / "test.csv").write_text(csv_content, encoding='utf-8')
    
    # Arquivo binário simples
    (samples_dir / "test.bin").write_bytes(b'\x00\x01\x02\x03\x04\x05')
    
    # Subdiretório com mais arquivos
    sub_dir = samples_dir / "subdir"
    sub_dir.mkdir()
    (sub_dir / "nested.txt").write_text("Arquivo aninhado", encoding='utf-8')
    
    return samples_dir


@pytest.fixture
def setup_logging():
    """Configura logging para testes"""
    setup_logger(level="DEBUG", console_output=False)


# Fixtures para dados de teste específicos
@pytest.fixture
def sample_analysis_result():
    """Retorna um resultado de análise de exemplo"""
    return {
        'session_id': 'test_session_001',
        'file_path': '/test/path/file.txt',
        'file_name': 'file.txt',
        'file_size': 1024,
        'file_type': 'Text',
        'analysis_type': 'DocumentAnalyzer',
        'success': True,
        'error_message': None,
        'analysis_duration': 0.05,
        'metadata': {
            'encoding': 'utf-8',
            'lines': 10,
            'words': 50
        },
        'hashes': {
            'md5': 'abc123def456',
            'sha1': 'def456ghi789',
            'sha256': 'ghi789jkl012'
        }
    }


@pytest.fixture
def sample_session_data():
    """Retorna dados de sessão de exemplo"""
    return {
        'session_id': 'test_session_001',
        'directory_path': '/test/directory',
        'total_files': 10,
        'processed_files': 8,
        'successful_files': 7,
        'failed_files': 1,
        'status': 'completed'
    }
