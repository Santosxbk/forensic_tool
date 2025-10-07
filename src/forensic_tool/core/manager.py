"""
Gerenciador principal de análises forenses, responsável por orquestrar todo o processo de análise.

Este módulo contém a classe `AnalysisManager`, que é o ponto central da lógica de negócio.
Ele coordena a varredura de arquivos, a execução de analisadores especializados, o cálculo de hashes,
_o armazenamento de resultados no banco de dados e o gerenciamento de análises concorrentes._
"""

import time
import threading
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable, Generator
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import logging
from dataclasses import dataclass

from ..analyzers import get_registry, register_all_analyzers, AnalysisResult
from ..utils import FileScanner, FileValidator, HashCalculator, get_forensic_logger
from .database import ResultsDatabase, AnalysisSession
from .config import get_config

logger = logging.getLogger(__name__)


@dataclass
class AnalysisProgress:
    """Estrutura de dados para representar o progresso de uma análise em tempo real."""
    session_id: str
    total_files: int
    processed_files: int
    successful_files: int
    failed_files: int
    current_file: str = ""
    start_time: datetime = None
    estimated_completion: Optional[datetime] = None
    
    @property
    def progress_percentage(self) -> float:
        """Calcula o percentual de progresso da análise."""
        if self.total_files == 0:
            return 0.0
        return (self.processed_files / self.total_files) * 100
    
    @property
    def success_rate(self) -> float:
        """Calcula a taxa de sucesso das análises de arquivos."""
        if self.processed_files == 0:
            return 0.0
        return (self.successful_files / self.processed_files) * 100


class AnalysisManager:
    """Gerenciador principal que orquestra as análises forenses."""
    
    def __init__(self, config=None, database=None):
        """
        Inicializa o AnalysisManager.

        Args:
            config (Config, optional): Objeto de configuração. Se None, usa a configuração global.
            database (ResultsDatabase, optional): Instância do banco de dados. Se None, cria uma nova.
        """
        self.config = config or get_config()
        self.database = database or ResultsDatabase(self.config.database.path)
        
        # Inicializa e registra todos os analisadores disponíveis
        self.registry = register_all_analyzers()
        
        # Inicializa os utilitários com base na configuração
        self.file_validator = FileValidator(
            max_path_depth=self.config.security.max_path_depth,
            allow_symlinks=self.config.security.allow_symlinks,
            blocked_extensions=set(self.config.security.blocked_extensions),
            max_file_size_mb=self.config.analysis.max_file_size_mb
        )
        
        self.file_scanner = FileScanner(
            validator=self.file_validator,
            supported_extensions=self.config.get_supported_extensions()
        )
        
        self.hash_calculator = HashCalculator(
            chunk_size=self.config.analysis.chunk_size,
            max_file_size_mb=self.config.analysis.max_file_size_mb,
            parallel_processing=True
        )
        
        # Estado interno para gerenciar análises ativas
        self._active_analyses: Dict[str, AnalysisProgress] = {}
        self._analysis_lock = threading.RLock()  # Lock para acesso thread-safe ao estado
        self._shutdown_event = threading.Event() # Evento para sinalizar o encerramento
        
        # Callbacks para notificação de progresso e conclusão
        self._progress_callbacks: List[Callable[[AnalysisProgress], None]] = []
        self._completion_callbacks: List[Callable[[str, Dict[str, Any]], None]] = []
        
        # Logger especializado para registrar eventos forenses
        self.forensic_logger = get_forensic_logger()
        
        logger.info("AnalysisManager inicializado com sucesso.")
    
    def add_progress_callback(self, callback: Callable[[AnalysisProgress], None]) -> None:
        """Adiciona um callback para ser notificado sobre o progresso da análise."""
        self._progress_callbacks.append(callback)
    
    def add_completion_callback(self, callback: Callable[[str, Dict[str, Any]], None]) -> None:
        """Adiciona um callback para ser notificado sobre a conclusão de uma análise."""
        self._completion_callbacks.append(callback)
    
    def start_analysis(self, 
                      session_id: str, 
                      directory_path: str,
                      include_hashes: bool = True,
                      max_files: Optional[int] = None) -> bool:
        """
        Inicia uma nova análise em um diretório.

        A análise é executada em uma thread separada para não bloquear a chamada principal.

        Args:
            session_id (str): Um ID único para a sessão de análise.
            directory_path (str): O caminho para o diretório a ser analisado.
            include_hashes (bool, optional): Se True, calcula os hashes dos arquivos. Padrão é True.
            max_files (int, optional): Número máximo de arquivos a serem analisados. Padrão é None (usa o limite da configuração).

        Returns:
            bool: True se a análise foi iniciada com sucesso, False caso contrário.
        """
        try:
            directory = Path(directory_path)
            
            # Valida o caminho do diretório para segurança e integridade
            is_valid, error = self.file_validator.validate_path(directory)
            if not is_valid:
                logger.error(f"Diretório inválido fornecido: {directory}. Motivo: {error}")
                return False
            
            # Garante que a mesma sessão não seja iniciada duas vezes
            with self._analysis_lock:
                if session_id in self._active_analyses:
                    logger.warning(f"Tentativa de iniciar análise com ID de sessão já em uso: {session_id}")
                    return False
            
            # Escaneia e conta os arquivos para ter uma estimativa do trabalho
            logger.info(f"Contando arquivos no diretório: {directory}")
            total_files = self.file_scanner.count_files(directory, max_count=max_files or self.config.analysis.max_files_per_analysis)
            
            if total_files == 0:
                logger.warning(f"Nenhum arquivo suportado encontrado para análise em {directory}")
                return False
            
            # Cria a sessão no banco de dados antes de iniciar o processamento
            if not self.database.create_analysis_session(session_id, str(directory), total_files):
                logger.error(f"Não foi possível criar a sessão de análise no banco de dados para {session_id}")
                return False
            
            # Inicializa o objeto de progresso da análise
            progress = AnalysisProgress(
                session_id=session_id,
                total_files=total_files,
                processed_files=0,
                successful_files=0,
                failed_files=0,
                start_time=datetime.now()
            )
            
            with self._analysis_lock:
                self._active_analyses[session_id] = progress
            
            # Registra o início da análise no log forense
            self.forensic_logger.log_analysis_start(session_id, str(directory), total_files)
            
            # Inicia a análise em uma nova thread para não bloquear a aplicação
            analysis_thread = threading.Thread(
                target=self._run_analysis,
                args=(session_id, directory, include_hashes, max_files),
                daemon=True,
                name=f"Analysis-{session_id}"
            )
            analysis_thread.start()
            
            logger.info(f"Análise {session_id} iniciada com sucesso para o diretório {directory}")
            return True
            
        except Exception as e:
            logger.critical(f"Erro crítico ao tentar iniciar a análise {session_id}: {e}", exc_info=True)
            return False
    
    def _run_analysis(self, 
                     session_id: str, 
                     directory: Path, 
                     include_hashes: bool,
                     max_files: Optional[int]) -> None:
        """
        Método privado que executa o loop principal da análise.

        Este método é executado em uma thread separada. Ele utiliza um ThreadPoolExecutor
        para processar os arquivos em paralelo, melhorando significativamente a performance.
        """
        try:
            start_time = time.time()
            
            with self._analysis_lock:
                progress = self._active_analyses.get(session_id)
            
            if not progress:
                logger.error(f"Estado de progresso não encontrado para a sessão {session_id} no início da execução.")
                return
            
            # Usa um ThreadPoolExecutor para análises concorrentes
            max_workers = min(self.config.analysis.thread_count, 8) # Limita o número de threads
            
            with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix=f"Analyzer-{session_id}") as executor:
                # Mapeia futuros para caminhos de arquivo para rastreamento
                future_to_file = {}
                
                # Submete cada arquivo para análise no pool de threads
                for file_path in self.file_scanner.scan_directory(directory, max_files=max_files):
                    if self._shutdown_event.is_set():
                        logger.info(f"Análise {session_id} cancelada devido a um pedido de encerramento.")
                        break
                    
                    future = executor.submit(
                        self._analyze_single_file,
                        file_path,
                        include_hashes
                    )
                    future_to_file[future] = file_path
                
                # Processa os resultados à medida que são concluídos
                for future in as_completed(future_to_file):
                    if self._shutdown_event.is_set():
                        break
                    
                    file_path = future_to_file[future]
                    
                    try:
                        result = future.result()
                        
                        # Persiste o resultado no banco de dados
                        self.database.save_analysis_result(session_id, result.to_dict())
                        
                        # Atualiza o estado de progresso de forma thread-safe
                        with self._analysis_lock:
                            if session_id in self._active_analyses:
                                progress = self._active_analyses[session_id]
                                progress.processed_files += 1
                                progress.current_file = file_path.name
                                
                                if result.success:
                                    progress.successful_files += 1
                                else:
                                    progress.failed_files += 1
                                
                                # Atualiza o progresso no banco de dados
                                self.database.update_session_progress(
                                    session_id,
                                    progress.processed_files,
                                    progress.successful_files,
                                    progress.failed_files
                                )
                                
                                # Notifica os callbacks de progresso
                                for callback in self._progress_callbacks:
                                    try:
                                        callback(progress)
                                    except Exception as e:
                                        logger.warning(f"Erro ao executar callback de progresso: {e}")
                                
                                # Log periódico para acompanhamento
                                if progress.processed_files % 100 == 0:
                                    self.forensic_logger.log_analysis_progress(
                                        session_id,
                                        progress.processed_files,
                                        progress.total_files,
                                        file_path.name
                                    )
                        
                    except Exception as e:
                        logger.error(f"Erro ao processar o resultado do arquivo {file_path}: {e}", exc_info=True)
                        
                        # Atualiza o contador de falhas em caso de erro inesperado
                        with self._analysis_lock:
                            if session_id in self._active_analyses:
                                progress = self._active_analyses[session_id]
                                progress.processed_files += 1
                                progress.failed_files += 1
            
            # Finalização da análise
            duration = time.time() - start_time
            
            with self._analysis_lock:
                if session_id in self._active_analyses:
                    progress = self._active_analyses[session_id]
                    
                    # Marca a sessão como concluída no banco
                    self.database.complete_analysis_session(session_id, "completed")
                    
                    # Registra a conclusão no log forense
                    self.forensic_logger.log_analysis_complete(
                        session_id,
                        duration,
                        progress.successful_files,
                        progress.failed_files
                    )
                    
                    # Notifica os callbacks de conclusão
                    stats = self.database.get_session_statistics(session_id)
                    for callback in self._completion_callbacks:
                        try:
                            callback(session_id, stats)
                        except Exception as e:
                            logger.warning(f"Erro ao executar callback de conclusão: {e}")
                    
                    # Remove a análise da lista de ativas
                    del self._active_analyses[session_id]
            
        except Exception as e:
            logger.critical(f"Erro fatal durante a execução da análise {session_id}: {e}", exc_info=True)
            
            # Em caso de erro fatal, marca a sessão como "error"
            self.database.complete_analysis_session(session_id, "error", str(e))
            
            with self._analysis_lock:
                if session_id in self._active_analyses:
                    del self._active_analyses[session_id]
    
    def _analyze_single_file(self, file_path: Path, include_hashes: bool) -> AnalysisResult:
        """
        Analisa um único arquivo, incluindo a seleção do analisador e o cálculo de hash.

        Args:
            file_path (Path): O caminho do arquivo a ser analisado.
            include_hashes (bool): Se True, calcula os hashes do arquivo.

        Returns:
            AnalysisResult: O resultado da análise do arquivo.
        """
        try:
            # Seleciona o analisador correto com base na extensão do arquivo
            analyzer = self.registry.get_analyzer_for_file(file_path)
            
            if not analyzer:
                return AnalysisResult(
                    file_path=str(file_path),
                    file_name=file_path.name,
                    file_size=file_path.stat().st_size if file_path.exists() else 0,
                    file_type="Unsupported",
                    analysis_type="None",
                    metadata={"error": "No analyzer found for this file type"},
                    success=False,
                    error_message="Nenhum analisador encontrado para este tipo de arquivo."
                )
            
            # Executa a análise principal
            result = analyzer.analyze(file_path)
            
            # Calcula hashes se a análise principal foi bem-sucedida e a opção está ativa
            if include_hashes and result.success:
                try:
                    hash_results = self.hash_calculator.calculate_multiple_hashes(
                        file_path,
                        self.config.analysis.hash_algorithms
                    )
                    
                    hashes = {algo: res.hash_value for algo, res in hash_results.items() if not res.error}
                    
                    if hashes:
                        result.metadata["hashes"] = hashes
                        
                except Exception as e:
                    logger.warning(f"Não foi possível calcular hashes para {file_path}: {e}")
                    result.metadata["hash_error"] = str(e)
            
            # Registra o resultado da análise do arquivo no log forense
            self.forensic_logger.log_file_analysis(
                str(file_path),
                result.file_type,
                result.success,
                result.error_message or ""
            )
            
            return result
            
        except Exception as e:
            logger.error(f"Erro inesperado ao analisar o arquivo {file_path}: {e}", exc_info=True)
            
            return AnalysisResult(
                file_path=str(file_path),
                file_name=file_path.name if file_path else "unknown",
                file_size=file_path.stat().st_size if file_path and file_path.exists() else 0,
                file_type="Error",
                analysis_type="Error",
                metadata={"critical_error": str(e)},
                success=False,
                error_message=f"Erro crítico na análise: {e}"
            )
    
    def get_analysis_progress(self, session_id: str) -> Optional[AnalysisProgress]:
        """Retorna o progresso atual de uma análise ativa."""
        with self._analysis_lock:
            return self._active_analyses.get(session_id)
    
    def get_active_analyses(self) -> List[str]:
        """Retorna uma lista com os IDs de todas as análises em execução."""
        with self._analysis_lock:
            return list(self._active_analyses.keys())
    
    def cancel_analysis(self, session_id: str) -> bool:
        """
        Cancela uma análise em andamento.

        Args:
            session_id (str): O ID da análise a ser cancelada.

        Returns:
            bool: True se a análise foi encontrada e o cancelamento iniciado, False caso contrário.
        """
        try:
            with self._analysis_lock:
                if session_id not in self._active_analyses:
                    logger.warning(f"Tentativa de cancelar uma análise inexistente ou já concluída: {session_id}")
                    return False
                
                # Marca a sessão como cancelada no banco de dados
                self.database.complete_analysis_session(session_id, "cancelled")
                
                # Remove da lista de análises ativas
                del self._active_analyses[session_id]
            
            logger.info(f"Análise {session_id} foi cancelada pelo usuário.")
            return True
            
        except Exception as e:
            logger.error(f"Erro ao tentar cancelar a análise {session_id}: {e}", exc_info=True)
            return False
    
    def get_analysis_results(self, session_id: str, **kwargs) -> List[Dict[str, Any]]:
        """Delega a busca de resultados de análise para o banco de dados."""
        return self.database.get_analysis_results(session_id, **kwargs)
    
    def get_session_statistics(self, session_id: str) -> Dict[str, Any]:
        """Delega a busca de estatísticas da sessão para o banco de dados."""
        return self.database.get_session_statistics(session_id)
    
    def get_analysis_session(self, session_id: str) -> Optional[AnalysisSession]:
        """Delega a busca de informações da sessão para o banco de dados."""
        return self.database.get_analysis_session(session_id)
    
    def find_duplicates(self, session_id: Optional[str] = None, hash_type: str = 'sha256') -> Dict[str, List[str]]:
        """Delega a busca por arquivos duplicados para o banco de dados."""
        return self.database.find_duplicates(session_id, hash_type)
    
    def get_recent_sessions(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Delega a busca por sessões recentes para o banco de dados."""
        return self.database.get_recent_sessions(limit)
    
    def cleanup_old_sessions(self, days_old: int = 30) -> int:
        """Delega a limpeza de sessões antigas para o banco de dados."""
        return self.database.cleanup_old_sessions(days_old)
    
    def get_supported_extensions(self) -> Dict[str, List[str]]:
        """Retorna um dicionário de extensões suportadas, agrupadas por categoria."""
        return self.config.analysis.supported_extensions.copy()
    
    def get_analyzer_info(self) -> List[Dict[str, Any]]:
        """Retorna informações sobre os analisadores registrados."""
        analyzers = self.registry.get_all_analyzers()
        return [
            {
                'name': analyzer.get_name(),
                'extensions': list(analyzer.get_supported_extensions()),
                'description': str(analyzer)
            }
            for analyzer in analyzers
        ]
    
    def shutdown(self) -> None:
        """
        Encerra o AnalysisManager de forma graciosa.

        Sinaliza para todas as análises em andamento pararem e fecha a conexão com o banco de dados.
        """
        logger.info("Iniciando o encerramento do AnalysisManager...")
        
        # Sinaliza para as threads de análise pararem
        self._shutdown_event.set()
        
        with self._analysis_lock:
            active_sessions = list(self._active_analyses.keys())
        
        # Cancela todas as análises ativas
        for session_id in active_sessions:
            self.cancel_analysis(session_id)
        
        # Fecha a conexão com o banco de dados
        self.database.close()
        
        logger.info("AnalysisManager encerrado com sucesso.")
    
    def __del__(self):
        """Garante que o shutdown seja chamado quando o objeto for destruído."""
        try:
            self.shutdown()
        except:
            pass
