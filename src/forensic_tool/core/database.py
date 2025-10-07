"""
Sistema de banco de dados para armazenamento de resultados de análise forense.

Este módulo fornece uma interface robusta para um banco de dados SQLite, projetada para
armazenar de forma eficiente os metadados extraídos, informações de sessão, hashes de arquivos
e estatísticas. Ele é thread-safe e utiliza um pool de conexões para gerenciar
acessos concorrentes, essencial para o ambiente multithread do AnalysisManager.
"""

import sqlite3
import json
import threading
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Union
from datetime import datetime, timedelta
import logging
from contextlib import contextmanager
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


@dataclass
class AnalysisSession:
    """Representa uma sessão de análise, contendo informações sobre o seu estado e progresso."""
    session_id: str
    directory_path: str
    total_files: int
    processed_files: int = 0
    successful_files: int = 0
    failed_files: int = 0
    start_time: datetime = None
    end_time: Optional[datetime] = None
    status: str = "running"  # running, completed, error, cancelled
    error_message: Optional[str] = None
    
    def __post_init__(self):
        """Inicializa o start_time se não for fornecido."""
        if self.start_time is None:
            self.start_time = datetime.now()
    
    @property
    def duration(self) -> Optional[timedelta]:
        """Calcula a duração total da sessão de análise."""
        if self.end_time:
            return self.end_time - self.start_time
        return None
    
    @property
    def progress_percentage(self) -> float:
        """Calcula o percentual de progresso da análise."""
        if self.total_files == 0:
            return 0.0
        return (self.processed_files / self.total_files) * 100
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte a instância da classe em um dicionário serializável."""
        data = asdict(self)
        # Converte objetos datetime para strings no formato ISO para serialização
        if self.start_time:
            data['start_time'] = self.start_time.isoformat()
        if self.end_time:
            data['end_time'] = self.end_time.isoformat()
        return data


class ResultsDatabase:
    """Classe que gerencia a conexão e as operações com o banco de dados SQLite."""
    
    def __init__(self, db_path: Union[str, Path] = "forensic_results.db"):
        """
        Inicializa a instância do banco de dados.

        Args:
            db_path (Union[str, Path], optional): O caminho para o arquivo do banco de dados. 
                                                  Padrão é "forensic_results.db".
        """
        self.db_path = Path(db_path)
        self._lock = threading.RLock()  # Lock para garantir thread safety
        self._connection_pool = {}  # Pool de conexões por thread ID
        self._init_database()
    
    def _init_database(self) -> None:
        """
        Cria as tabelas necessárias no banco de dados se elas não existirem.
        Define o esquema, incluindo tabelas para sessões, resultados, hashes e estatísticas,
        além de índices para otimizar as consultas.
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Tabela para armazenar informações sobre cada sessão de análise
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS analysis_sessions (
                        session_id TEXT PRIMARY KEY,
                        directory_path TEXT NOT NULL,
                        total_files INTEGER DEFAULT 0,
                        processed_files INTEGER DEFAULT 0,
                        successful_files INTEGER DEFAULT 0,
                        failed_files INTEGER DEFAULT 0,
                        start_time TEXT NOT NULL,
                        end_time TEXT,
                        status TEXT DEFAULT 'running',
                        error_message TEXT,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Tabela principal para armazenar os resultados detalhados de cada arquivo analisado
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS analysis_results (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        session_id TEXT NOT NULL,
                        file_path TEXT NOT NULL,
                        file_name TEXT NOT NULL,
                        file_size INTEGER DEFAULT 0,
                        file_type TEXT,
                        analysis_type TEXT,
                        success BOOLEAN DEFAULT 0,
                        error_message TEXT,
                        analysis_duration REAL DEFAULT 0,
                        metadata_json TEXT, -- Armazena metadados complexos como JSON
                        hash_md5 TEXT,
                        hash_sha1 TEXT,
                        hash_sha256 TEXT,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (session_id) REFERENCES analysis_sessions (session_id) ON DELETE CASCADE
                    )
                """)
                
                # Tabela otimizada para busca de duplicatas por hash
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS file_hashes (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        file_path TEXT NOT NULL,
                        file_size INTEGER NOT NULL,
                        hash_md5 TEXT,
                        hash_sha1 TEXT,
                        hash_sha256 TEXT,
                        first_seen TEXT DEFAULT CURRENT_TIMESTAMP,
                        last_seen TEXT DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(file_path, file_size) -- Evita duplicatas na própria tabela
                    )
                """)
                
                # Tabela para estatísticas agregadas por sessão
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS analysis_statistics (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        session_id TEXT NOT NULL,
                        statistic_name TEXT NOT NULL,
                        statistic_value TEXT NOT NULL,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (session_id) REFERENCES analysis_sessions (session_id) ON DELETE CASCADE
                    )
                """)
                
                # Índices para acelerar consultas comuns
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_results_session ON analysis_results(session_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_results_file_path ON analysis_results(file_path)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_results_file_type ON analysis_results(file_type)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_results_success ON analysis_results(success)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_hashes_md5 ON file_hashes(hash_md5)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_hashes_sha256 ON file_hashes(hash_sha256)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_sessions_status ON analysis_sessions(status)")
                
                conn.commit()
                logger.info(f"Banco de dados inicializado com sucesso em: {self.db_path}")
                
        except Exception as e:
            logger.critical(f"Falha crítica ao inicializar o banco de dados: {e}", exc_info=True)
            raise
    
    @contextmanager
    def _get_connection(self):
        """
        Gerenciador de contexto para obter uma conexão de banco de dados do pool.
        Cria uma nova conexão por thread se uma não existir.
        """
        thread_id = threading.get_ident()
        
        with self._lock:
            if thread_id not in self._connection_pool:
                try:
                    conn = sqlite3.connect(
                        self.db_path,
                        timeout=30.0,  # Timeout para operações de escrita
                        check_same_thread=False # Permite o uso em móltiplas threads
                    )
                    conn.row_factory = sqlite3.Row # Acesso aos resultados por nome de coluna
                    conn.execute("PRAGMA foreign_keys = ON") # Habilita o suporte a chaves estrangeiras
                    conn.execute("PRAGMA journal_mode = WAL") # Melhora a concorrância
                    self._connection_pool[thread_id] = conn
                except Exception as e:
                    logger.error(f"Falha ao criar conexão com o banco de dados para a thread {thread_id}: {e}")
                    raise
            
            conn = self._connection_pool[thread_id]
        
        try:
            yield conn
        except Exception as e:
            conn.rollback() # Desfaz a transação em caso de erro
            raise
        finally:
            # A conexão não é fechada aqui para ser reutilizada pela mesma thread
            pass
    
    def create_analysis_session(self, session_id: str, directory_path: str, total_files: int = 0) -> bool:
        """
        Cria um novo registro de sessão de análise no banco de dados.

        Args:
            session_id (str): O ID ùnico para a nova sessão.
            directory_path (str): O caminho do diretório que será analisado.
            total_files (int, optional): O número total de arquivos a serem analisados. Padrão é 0.

        Returns:
            bool: True se a sessão foi criada com sucesso, False caso contrário.
        """
        try:
            session = AnalysisSession(
                session_id=session_id,
                directory_path=directory_path,
                total_files=total_files
            )
            
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO analysis_sessions 
                    (session_id, directory_path, total_files, start_time, status)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    session.session_id,
                    session.directory_path,
                    session.total_files,
                    session.start_time.isoformat(),
                    session.status
                ))
                conn.commit()
            
            logger.info(f"Sessão de análise {session_id} criada com sucesso.")
            return True
            
        except Exception as e:
            logger.error(f"Erro ao criar a sessão de análise {session_id}: {e}", exc_info=True)
            return False
    
    def update_session_progress(self, session_id: str, processed_files: int, successful_files: int, failed_files: int) -> bool:
        """
        Atualiza o progresso de uma sessão de análise existente.

        Args:
            session_id (str): O ID da sessão a ser atualizada.
            processed_files (int): O número total de arquivos processados até o momento.
            successful_files (int): O número de arquivos analisados com sucesso.
            failed_files (int): O número de arquivos que falharam na análise.

        Returns:
            bool: True se a atualização foi bem-sucedida, False caso contrário.
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE analysis_sessions 
                    SET processed_files = ?, successful_files = ?, failed_files = ?
                    WHERE session_id = ?
                """, (processed_files, successful_files, failed_files, session_id))
                conn.commit()
            
            return cursor.rowcount > 0
            
        except Exception as e:
            logger.error(f"Erro ao atualizar o progresso da sessão {session_id}: {e}", exc_info=True)
            return False
    
    def complete_analysis_session(self, session_id: str, status: str = "completed", error_message: Optional[str] = None) -> bool:
        """
        Marca uma sessão de análise como concluída, definindo seu status final e tempo de término.

        Args:
            session_id (str): O ID da sessão a ser finalizada.
            status (str, optional): O status final da sessão ('completed', 'error', 'cancelled'). Padrão é 'completed'.
            error_message (Optional[str], optional): Uma mensagem de erro, se aplicável. Padrão é None.

        Returns:
            bool: True se a sessão foi marcada como concluída, False caso contrário.
        """
        try:
            end_time = datetime.now().isoformat()
            
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE analysis_sessions 
                    SET status = ?, end_time = ?, error_message = ?
                    WHERE session_id = ?
                """, (status, end_time, error_message, session_id))
                conn.commit()
            
            logger.info(f"Sessão {session_id} finalizada com o status: {status}")
            return cursor.rowcount > 0
            
        except Exception as e:
            logger.error(f"Erro ao finalizar a sessão {session_id}: {e}", exc_info=True)
            return False
    
    def save_analysis_result(self, session_id: str, result: Dict[str, Any]) -> bool:
        """
        Salva o resultado da análise de um ùnico arquivo no banco de dados.

        Args:
            session_id (str): O ID da sessão à qual este resultado pertence.
            result (Dict[str, Any]): Um dicionário contendo os dados da análise do arquivo.

        Returns:
            bool: True se o resultado foi salvo com sucesso, False caso contrário.
        """
        try:
            # Extrai os hashes do resultado, se existirem
            hashes = result.get('hashes', {})
            hash_md5 = hashes.get('md5')
            hash_sha1 = hashes.get('sha1')
            hash_sha256 = hashes.get('sha256')
            
            # Prepara os metadados para serem armazenados como uma string JSON
            metadata = result.copy()
            if 'hashes' in metadata: # Remove os hashes do JSON para evitar redundância
                del metadata['hashes']
            
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Insere o resultado da análise
                cursor.execute("""
                    INSERT INTO analysis_results 
                    (session_id, file_path, file_name, file_size, file_type, 
                     analysis_type, success, error_message, analysis_duration, 
                     metadata_json, hash_md5, hash_sha1, hash_sha256)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    session_id,
                    str(result.get('file_path', '')),
                    result.get('file_name', ''),
                    result.get('file_size', 0),
                    result.get('file_type', ''),
                    result.get('analysis_type', ''),
                    result.get('success', False),
                    result.get('error_message'),
                    result.get('analysis_duration', 0.0),
                    json.dumps(metadata, default=str), # Serializa o dicionário de metadados
                    hash_md5,
                    hash_sha1,
                    hash_sha256
                ))
                
                # Atualiza ou insere o hash na tabela de hashes para detecção de duplicatas
                if any([hash_md5, hash_sha1, hash_sha256]):
                    self._upsert_file_hash(
                        cursor,
                        str(result.get('file_path', '')),
                        result.get('file_size', 0),
                        hash_md5,
                        hash_sha1,
                        hash_sha256
                    )
                
                conn.commit()
            
            return True
            
        except Exception as e:
            logger.error(f"Erro ao salvar resultado para o arquivo {result.get('file_path')} na sessão {session_id}: {e}", exc_info=True)
            return False
    
    def _upsert_file_hash(self, cursor, file_path: str, file_size: int, 
                         hash_md5: Optional[str], hash_sha1: Optional[str], hash_sha256: Optional[str]) -> None:
        """
        Insere um novo registro de hash ou atualiza um existente (upsert).
        Utilizado para manter um catálogo de hashes de arquivos para detecção de duplicatas.
        """
        try:
            now = datetime.now().isoformat()
            
            # Tenta inserir o hash. Se já existir (devido à constraint UNIQUE), ignora.
            cursor.execute("""
                INSERT OR IGNORE INTO file_hashes 
                (file_path, file_size, hash_md5, hash_sha1, hash_sha256, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (file_path, file_size, hash_md5, hash_sha1, hash_sha256, now, now))
            
            # Se a inserção foi ignorada (rowcount == 0), atualiza o registro existente
            if cursor.rowcount == 0:
                cursor.execute("""
                    UPDATE file_hashes 
                    SET hash_md5 = COALESCE(?, hash_md5), -- Só atualiza se o novo valor não for nulo
                        hash_sha1 = COALESCE(?, hash_sha1),
                        hash_sha256 = COALESCE(?, hash_sha256),
                        last_seen = ?
                    WHERE file_path = ? AND file_size = ?
                """, (hash_md5, hash_sha1, hash_sha256, now, file_path, file_size))
                
        except Exception as e:
            logger.warning(f"Não foi possível fazer o upsert do hash para o arquivo {file_path}: {e}")

    def get_analysis_session(self, session_id: str) -> Optional[AnalysisSession]:
        """
        Recupera os detalhes de uma sessão de análise específica.

        Args:
            session_id (str): O ID da sessão a ser recuperada.

        Returns:
            Optional[AnalysisSession]: Um objeto AnalysisSession com os dados da sessão, ou None se não for encontrada.
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM analysis_sessions WHERE session_id = ?", (session_id,))
                
                row = cursor.fetchone()
                if not row:
                    return None
                
                # Converte a linha do banco de dados de volta para um objeto AnalysisSession
                session = AnalysisSession(
                    session_id=row['session_id'],
                    directory_path=row['directory_path'],
                    total_files=row['total_files'],
                    processed_files=row['processed_files'],
                    successful_files=row['successful_files'],
                    failed_files=row['failed_files'],
                    start_time=datetime.fromisoformat(row['start_time']),
                    end_time=datetime.fromisoformat(row['end_time']) if row['end_time'] else None,
                    status=row['status'],
                    error_message=row['error_message']
                )
                
                return session
                
        except Exception as e:
            logger.error(f"Erro ao obter a sessão {session_id}: {e}", exc_info=True)
            return None

    def get_analysis_results(self, session_id: str, limit: int = 1000, offset: int = 0, 
                           file_type: Optional[str] = None, success_only: bool = False) -> List[Dict[str, Any]]:
        """
        Recupera uma lista de resultados de análise para uma determinada sessão, com opções de filtragem e paginação.

        Args:
            session_id (str): O ID da sessão.
            limit (int, optional): O número máximo de resultados a serem retornados. Padrão é 1000.
            offset (int, optional): O número de resultados a serem ignorados (para paginação). Padrão é 0.
            file_type (Optional[str], optional): Filtra os resultados por tipo de arquivo. Padrão é None.
            success_only (bool, optional): Se True, retorna apenas os resultados de análises bem-sucedidas. Padrão é False.

        Returns:
            List[Dict[str, Any]]: Uma lista de dicionários, onde cada dicionário representa um resultado de análise.
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Constrói a query dinamicamente com base nos filtros fornecidos
                query = "SELECT * FROM analysis_results WHERE session_id = ?"
                params = [session_id]
                
                if file_type:
                    query += " AND file_type = ?"
                    params.append(file_type)
                
                if success_only:
                    query += " AND success = 1"
                
                query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
                params.extend([limit, offset])
                
                cursor.execute(query, tuple(params))
                rows = cursor.fetchall()
                
                results = []
                for row in rows:
                    result = dict(row)
                    
                    # Desserializa a string JSON de metadados de volta para um dicionário Python
                    if result.get('metadata_json'):
                        try:
                            result['metadata'] = json.loads(result['metadata_json'])
                        except json.JSONDecodeError:
                            result['metadata'] = {'error': 'Falha ao decodificar JSON'}
                    else:
                        result['metadata'] = {}
                    
                    # Adiciona os hashes a um sub-dicionário para melhor organização
                    result['hashes'] = {
                        'md5': result.get('hash_md5'),
                        'sha1': result.get('hash_sha1'),
                        'sha256': result.get('hash_sha256')
                    }
                    
                    # Remove campos internos/redundantes
                    del result['metadata_json']
                    
                    results.append(result)
                
                return results
                
        except Exception as e:
            logger.error(f"Erro ao obter resultados da sessão {session_id}: {e}", exc_info=True)
            return []

    def get_session_statistics(self, session_id: str) -> Dict[str, Any]:
        """
        Calcula e recupera estatísticas agregadas para uma sessão de análise.

        Args:
            session_id (str): O ID da sessão.

        Returns:
            Dict[str, Any]: Um dicionário contendo várias estatísticas, como contagens, taxas e listas de top-N.
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Estatísticas gerais da sessão
                cursor.execute("""
                    SELECT 
                        COUNT(*) as total_results,
                        SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful,
                        SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) as failed,
                        AVG(analysis_duration) as avg_duration,
                        SUM(file_size) as total_size
                    FROM analysis_results 
                    WHERE session_id = ?
                """, (session_id,))
                
                stats_row = cursor.fetchone()
                
                # Contagem de arquivos por tipo
                cursor.execute("""
                    SELECT file_type, COUNT(*) as count
                    FROM analysis_results 
                    WHERE session_id = ? AND success = 1
                    GROUP BY file_type
                    ORDER BY count DESC
                """, (session_id,))
                
                file_types = {row['file_type']: row['count'] for row in cursor.fetchall()}
                
                # Top 10 maiores arquivos analisados com sucesso
                cursor.execute("""
                    SELECT file_path, file_name, file_size
                    FROM analysis_results 
                    WHERE session_id = ? AND success = 1
                    ORDER BY file_size DESC
                    LIMIT 10
                """, (session_id,))
                
                largest_files = [dict(row) for row in cursor.fetchall()]
                
                total_results = stats_row['total_results'] or 0
                successful = stats_row['successful'] or 0
                total_size = stats_row['total_size'] or 0

                return {
                    'total_results': total_results,
                    'successful': successful,
                    'failed': stats_row['failed'] or 0,
                    'success_rate': (successful / total_results * 100) if total_results > 0 else 0,
                    'average_duration': stats_row['avg_duration'] or 0,
                    'total_size_bytes': total_size,
                    'total_size_mb': total_size / (1024 * 1024),
                    'file_types': file_types,
                    'largest_files': largest_files
                }
                
        except Exception as e:
            logger.error(f"Erro ao obter estatísticas da sessão {session_id}: {e}", exc_info=True)
            return {}

    def find_duplicates(self, session_id: Optional[str] = None, hash_type: str = 'sha256') -> Dict[str, List[str]]:
        """
        Encontra arquivos duplicados com base em seus hashes.

        Args:
            session_id (Optional[str], optional): O ID da sessão para limitar a busca. Se None, busca em todos os arquivos já hasheados. Padrão é None.
            hash_type (str, optional): O tipo de hash a ser usado para a comparação ('md5', 'sha1', 'sha256'). Padrão é 'sha256'.

        Returns:
            Dict[str, List[str]]: Um dicionário onde as chaves são os hashes e os valores são listas de caminhos de arquivos duplicados.
        """
        try:
            hash_column = f'hash_{hash_type.lower()}'
            
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                if session_id:
                    # Busca duplicatas dentro de uma sessão específica
                    query = f"""
                        SELECT {hash_column}, GROUP_CONCAT(file_path) as paths
                        FROM analysis_results 
                        WHERE session_id = ? AND {hash_column} IS NOT NULL AND success = 1
                        GROUP BY {hash_column}
                        HAVING COUNT(*) > 1
                    """
                    cursor.execute(query, (session_id,))
                else:
                    # Busca duplicatas em todo o banco de dados de hashes
                    query = f"""
                        SELECT {hash_column}, GROUP_CONCAT(file_path) as paths
                        FROM file_hashes 
                        WHERE {hash_column} IS NOT NULL
                        GROUP BY {hash_column}
                        HAVING COUNT(*) > 1
                    """
                    cursor.execute(query)
                
                duplicates = {}
                for row in cursor.fetchall():
                    hash_value = row[hash_column]
                    paths = row['paths'].split(',') if row['paths'] else []
                    duplicates[hash_value] = paths
                
                return duplicates
                
        except Exception as e:
            logger.error(f"Erro ao encontrar arquivos duplicados: {e}", exc_info=True)
            return {}

    def get_recent_sessions(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Recupera uma lista das sessões de análise mais recentes.

        Args:
            limit (int, optional): O número máximo de sessões a serem retornadas. Padrão é 10.

        Returns:
            List[Dict[str, Any]]: Uma lista de dicionários, cada um representando uma sessão.
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM analysis_sessions ORDER BY created_at DESC LIMIT ?", (limit,))
                
                return [dict(row) for row in cursor.fetchall()]
                
        except Exception as e:
            logger.error(f"Erro ao obter sessões recentes: {e}", exc_info=True)
            return []

    def cleanup_old_sessions(self, days_old: int = 30) -> int:
        """
        Remove sessões de análise e seus resultados associados que são mais antigos que um determinado número de dias.

        Args:
            days_old (int, optional): A idade mínima em dias para que uma sessão seja removida. Padrão é 30.

        Returns:
            int: O número de sessões que foram removidas.
        """
        try:
            cutoff_date = datetime.now() - timedelta(days=days_old)
            
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Primeiro, remove os resultados associados para manter a integridade referencial
                cursor.execute("""
                    DELETE FROM analysis_results 
                    WHERE session_id IN (
                        SELECT session_id FROM analysis_sessions 
                        WHERE created_at < ?
                    )
                """, (cutoff_date.isoformat(),))
                
                # Depois, remove as próprias sessões
                cursor.execute("DELETE FROM analysis_sessions WHERE created_at < ?", (cutoff_date.isoformat(),))
                
                removed_count = cursor.rowcount
                conn.commit()
                
                if removed_count > 0:
                    logger.info(f"{removed_count} sessões antigas foram removidas com sucesso.")
                return removed_count
                
        except Exception as e:
            logger.error(f"Erro durante a limpeza de sessões antigas: {e}", exc_info=True)
            return 0

    def close(self) -> None:
        """Fecha todas as conexões de banco de dados no pool de conexões."""
        with self._lock:
            for thread_id, conn in self._connection_pool.items():
                try:
                    conn.close()
                except Exception as e:
                    logger.warning(f"Erro ao fechar a conexão para a thread {thread_id}: {e}")
            self._connection_pool.clear()
        
        logger.info("Todas as conexões do banco de dados foram fechadas.")
    
    def __del__(self):
        """Destrutor para garantir que as conexões sejam fechadas quando o objeto for coletado."""
        try:
            self.close()
        except:
            pass
