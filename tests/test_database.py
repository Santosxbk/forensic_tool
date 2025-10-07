"""
Testes para o módulo de banco de dados
"""

import pytest
from datetime import datetime, timedelta
from pathlib import Path

from src.forensic_tool.core.database import ResultsDatabase, AnalysisSession


class TestResultsDatabase:
    """Testes para a classe ResultsDatabase"""
    
    def test_database_initialization(self, test_database: ResultsDatabase):
        """Testa se o banco de dados é inicializado corretamente"""
        assert test_database.db_path.exists()
        
        # Verifica se as tabelas foram criadas
        with test_database._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            
            expected_tables = [
                'analysis_sessions',
                'analysis_results', 
                'file_hashes',
                'analysis_statistics'
            ]
            
            for table in expected_tables:
                assert table in tables
    
    def test_create_analysis_session(self, test_database: ResultsDatabase):
        """Testa a criação de uma sessão de análise"""
        session_id = "test_session_001"
        directory_path = "/test/directory"
        total_files = 10
        
        # Cria a sessão
        success = test_database.create_analysis_session(session_id, directory_path, total_files)
        assert success
        
        # Verifica se foi criada corretamente
        session = test_database.get_analysis_session(session_id)
        assert session is not None
        assert session.session_id == session_id
        assert session.directory_path == directory_path
        assert session.total_files == total_files
        assert session.status == "running"
    
    def test_update_session_progress(self, test_database: ResultsDatabase):
        """Testa a atualização do progresso da sessão"""
        session_id = "test_session_002"
        
        # Cria a sessão
        test_database.create_analysis_session(session_id, "/test", 10)
        
        # Atualiza o progresso
        success = test_database.update_session_progress(session_id, 5, 4, 1)
        assert success
        
        # Verifica a atualização
        session = test_database.get_analysis_session(session_id)
        assert session.processed_files == 5
        assert session.successful_files == 4
        assert session.failed_files == 1
    
    def test_complete_analysis_session(self, test_database: ResultsDatabase):
        """Testa a finalização de uma sessão"""
        session_id = "test_session_003"
        
        # Cria a sessão
        test_database.create_analysis_session(session_id, "/test", 5)
        
        # Finaliza a sessão
        success = test_database.complete_analysis_session(session_id, "completed")
        assert success
        
        # Verifica a finalização
        session = test_database.get_analysis_session(session_id)
        assert session.status == "completed"
        assert session.end_time is not None
    
    def test_save_analysis_result(self, test_database: ResultsDatabase, sample_analysis_result):
        """Testa o salvamento de resultado de análise"""
        session_id = "test_session_004"
        
        # Cria a sessão
        test_database.create_analysis_session(session_id, "/test", 1)
        
        # Salva o resultado
        sample_analysis_result['session_id'] = session_id
        success = test_database.save_analysis_result(session_id, sample_analysis_result)
        assert success
        
        # Verifica se foi salvo
        results = test_database.get_analysis_results(session_id)
        assert len(results) == 1
        
        result = results[0]
        assert result['file_name'] == sample_analysis_result['file_name']
        assert result['file_type'] == sample_analysis_result['file_type']
        assert result['success'] == sample_analysis_result['success']
    
    def test_get_session_statistics(self, test_database: ResultsDatabase, sample_analysis_result):
        """Testa a obtenção de estatísticas da sessão"""
        session_id = "test_session_005"
        
        # Cria a sessão
        test_database.create_analysis_session(session_id, "/test", 2)
        
        # Adiciona alguns resultados
        sample_analysis_result['session_id'] = session_id
        test_database.save_analysis_result(session_id, sample_analysis_result)
        
        # Adiciona um resultado com falha
        failed_result = sample_analysis_result.copy()
        failed_result['success'] = False
        failed_result['file_name'] = 'failed_file.txt'
        test_database.save_analysis_result(session_id, failed_result)
        
        # Obtém estatísticas
        stats = test_database.get_session_statistics(session_id)
        
        assert stats['total_results'] == 2
        assert stats['successful'] == 1
        assert stats['failed'] == 1
        assert stats['success_rate'] == 50.0
    
    def test_find_duplicates(self, test_database: ResultsDatabase):
        """Testa a detecção de arquivos duplicados"""
        session_id = "test_session_006"
        test_database.create_analysis_session(session_id, "/test", 3)
        
        # Cria resultados com o mesmo hash
        same_hash = "abc123def456ghi789"
        
        result1 = {
            'session_id': session_id,
            'file_path': '/test/file1.txt',
            'file_name': 'file1.txt',
            'file_size': 1024,
            'file_type': 'Text',
            'analysis_type': 'DocumentAnalyzer',
            'success': True,
            'hashes': {'sha256': same_hash}
        }
        
        result2 = {
            'session_id': session_id,
            'file_path': '/test/file2.txt',
            'file_name': 'file2.txt',
            'file_size': 1024,
            'file_type': 'Text',
            'analysis_type': 'DocumentAnalyzer',
            'success': True,
            'hashes': {'sha256': same_hash}
        }
        
        test_database.save_analysis_result(session_id, result1)
        test_database.save_analysis_result(session_id, result2)
        
        # Busca duplicatas
        duplicates = test_database.find_duplicates(session_id, 'sha256')
        
        assert len(duplicates) == 1
        assert same_hash in duplicates
        assert len(duplicates[same_hash]) == 2
    
    def test_cleanup_old_sessions(self, test_database: ResultsDatabase):
        """Testa a limpeza de sessões antigas"""
        # Cria uma sessão "antiga" modificando diretamente o banco
        session_id = "old_session"
        test_database.create_analysis_session(session_id, "/test", 1)
        
        # Modifica a data de criação para ser antiga
        old_date = (datetime.now() - timedelta(days=40)).isoformat()
        
        with test_database._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE analysis_sessions SET created_at = ? WHERE session_id = ?",
                (old_date, session_id)
            )
            conn.commit()
        
        # Executa limpeza
        removed_count = test_database.cleanup_old_sessions(days_old=30)
        
        assert removed_count == 1
        
        # Verifica se foi removida
        session = test_database.get_analysis_session(session_id)
        assert session is None


class TestAnalysisSession:
    """Testes para a classe AnalysisSession"""
    
    def test_analysis_session_creation(self):
        """Testa a criação de uma sessão de análise"""
        session = AnalysisSession(
            session_id="test_001",
            directory_path="/test/path",
            total_files=10
        )
        
        assert session.session_id == "test_001"
        assert session.directory_path == "/test/path"
        assert session.total_files == 10
        assert session.processed_files == 0
        assert session.status == "running"
        assert session.start_time is not None
    
    def test_progress_percentage(self):
        """Testa o cálculo de percentual de progresso"""
        session = AnalysisSession(
            session_id="test_002",
            directory_path="/test",
            total_files=10,
            processed_files=5
        )
        
        assert session.progress_percentage == 50.0
        
        # Teste com total_files = 0
        session.total_files = 0
        assert session.progress_percentage == 0.0
    
    def test_duration_calculation(self):
        """Testa o cálculo de duração da sessão"""
        start_time = datetime.now()
        session = AnalysisSession(
            session_id="test_003",
            directory_path="/test",
            total_files=5,
            start_time=start_time
        )
        
        # Sem end_time, duração deve ser None
        assert session.duration is None
        
        # Com end_time, deve calcular a duração
        session.end_time = start_time + timedelta(minutes=5)
        assert session.duration == timedelta(minutes=5)
    
    def test_to_dict(self):
        """Testa a conversão para dicionário"""
        start_time = datetime.now()
        session = AnalysisSession(
            session_id="test_004",
            directory_path="/test",
            total_files=3,
            start_time=start_time
        )
        
        session_dict = session.to_dict()
        
        assert session_dict['session_id'] == "test_004"
        assert session_dict['directory_path'] == "/test"
        assert session_dict['total_files'] == 3
        assert session_dict['start_time'] == start_time.isoformat()
        assert session_dict['end_time'] is None
