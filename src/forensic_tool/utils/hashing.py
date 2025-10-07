"""
Sistema de cálculo de hashes otimizado para Forensic Tool
"""

import hashlib
import hmac
from pathlib import Path
from typing import Dict, List, Optional, Union, Callable, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import time
from dataclasses import dataclass
import mmap

logger = logging.getLogger(__name__)


@dataclass
class HashResult:
    """Resultado do cálculo de hash"""
    algorithm: str
    hash_value: str
    file_path: str
    file_size: int
    calculation_time: float
    error: Optional[str] = None


class HashCalculator:
    """Calculadora de hashes otimizada"""
    
    # Algoritmos suportados
    SUPPORTED_ALGORITHMS = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha224': hashlib.sha224,
        'sha256': hashlib.sha256,
        'sha384': hashlib.sha384,
        'sha512': hashlib.sha512,
        'blake2b': hashlib.blake2b,
        'blake2s': hashlib.blake2s,
    }
    
    def __init__(self, 
                 chunk_size: int = 8192,
                 max_file_size_mb: int = 1024,
                 use_mmap: bool = True,
                 parallel_processing: bool = True):
        """
        Inicializa o calculador de hashes
        
        Args:
            chunk_size: Tamanho do chunk em bytes
            max_file_size_mb: Tamanho máximo de arquivo em MB
            use_mmap: Se deve usar memory mapping para arquivos grandes
            parallel_processing: Se deve usar processamento paralelo
        """
        self.chunk_size = chunk_size
        self.max_file_size_bytes = max_file_size_mb * 1024 * 1024
        self.use_mmap = use_mmap
        self.parallel_processing = parallel_processing
        
        # Limites para diferentes estratégias
        self.small_file_limit = 1024 * 1024  # 1MB
        self.mmap_threshold = 10 * 1024 * 1024  # 10MB
    
    def calculate_single_hash(self, 
                            file_path: Path, 
                            algorithm: str) -> HashResult:
        """
        Calcula hash único para um arquivo
        
        Args:
            file_path: Caminho do arquivo
            algorithm: Algoritmo de hash
            
        Returns:
            Resultado do cálculo
        """
        start_time = time.time()
        
        try:
            # Verificar se algoritmo é suportado
            if algorithm not in self.SUPPORTED_ALGORITHMS:
                return HashResult(
                    algorithm=algorithm,
                    hash_value="",
                    file_path=str(file_path),
                    file_size=0,
                    calculation_time=0,
                    error=f"Algoritmo não suportado: {algorithm}"
                )
            
            # Verificar se arquivo existe
            if not file_path.exists() or not file_path.is_file():
                return HashResult(
                    algorithm=algorithm,
                    hash_value="",
                    file_path=str(file_path),
                    file_size=0,
                    calculation_time=0,
                    error="Arquivo não encontrado"
                )
            
            file_size = file_path.stat().st_size
            
            # Verificar tamanho máximo
            if file_size > self.max_file_size_bytes:
                return HashResult(
                    algorithm=algorithm,
                    hash_value="",
                    file_path=str(file_path),
                    file_size=file_size,
                    calculation_time=0,
                    error=f"Arquivo muito grande: {file_size / (1024*1024):.1f}MB"
                )
            
            # Escolher estratégia baseada no tamanho
            if file_size == 0:
                hash_value = self._calculate_empty_file_hash(algorithm)
            elif file_size <= self.small_file_limit:
                hash_value = self._calculate_small_file_hash(file_path, algorithm)
            elif self.use_mmap and file_size >= self.mmap_threshold:
                hash_value = self._calculate_mmap_hash(file_path, algorithm)
            else:
                hash_value = self._calculate_chunked_hash(file_path, algorithm)
            
            calculation_time = time.time() - start_time
            
            return HashResult(
                algorithm=algorithm,
                hash_value=hash_value,
                file_path=str(file_path),
                file_size=file_size,
                calculation_time=calculation_time
            )
            
        except Exception as e:
            calculation_time = time.time() - start_time
            logger.error(f"Erro ao calcular hash {algorithm} para {file_path}: {e}")
            
            return HashResult(
                algorithm=algorithm,
                hash_value="",
                file_path=str(file_path),
                file_size=file_path.stat().st_size if file_path.exists() else 0,
                calculation_time=calculation_time,
                error=str(e)
            )
    
    def calculate_multiple_hashes(self, 
                                file_path: Path, 
                                algorithms: List[str]) -> Dict[str, HashResult]:
        """
        Calcula múltiplos hashes para um arquivo
        
        Args:
            file_path: Caminho do arquivo
            algorithms: Lista de algoritmos
            
        Returns:
            Dicionário com resultados por algoritmo
        """
        results = {}
        
        try:
            # Verificações básicas
            if not file_path.exists() or not file_path.is_file():
                error_msg = "Arquivo não encontrado"
                for algo in algorithms:
                    results[algo] = HashResult(
                        algorithm=algo,
                        hash_value="",
                        file_path=str(file_path),
                        file_size=0,
                        calculation_time=0,
                        error=error_msg
                    )
                return results
            
            file_size = file_path.stat().st_size
            
            # Verificar tamanho
            if file_size > self.max_file_size_bytes:
                error_msg = f"Arquivo muito grande: {file_size / (1024*1024):.1f}MB"
                for algo in algorithms:
                    results[algo] = HashResult(
                        algorithm=algo,
                        hash_value="",
                        file_path=str(file_path),
                        file_size=file_size,
                        calculation_time=0,
                        error=error_msg
                    )
                return results
            
            # Calcular todos os hashes em uma única passada
            start_time = time.time()
            hash_values = self._calculate_multiple_hashes_single_pass(file_path, algorithms)
            calculation_time = time.time() - start_time
            
            # Criar resultados
            for algo in algorithms:
                if algo in hash_values:
                    results[algo] = HashResult(
                        algorithm=algo,
                        hash_value=hash_values[algo],
                        file_path=str(file_path),
                        file_size=file_size,
                        calculation_time=calculation_time / len(algorithms)  # Dividir tempo
                    )
                else:
                    results[algo] = HashResult(
                        algorithm=algo,
                        hash_value="",
                        file_path=str(file_path),
                        file_size=file_size,
                        calculation_time=0,
                        error=f"Algoritmo não suportado: {algo}"
                    )
                    
        except Exception as e:
            logger.error(f"Erro ao calcular múltiplos hashes para {file_path}: {e}")
            for algo in algorithms:
                results[algo] = HashResult(
                    algorithm=algo,
                    hash_value="",
                    file_path=str(file_path),
                    file_size=0,
                    calculation_time=0,
                    error=str(e)
                )
        
        return results
    
    def calculate_batch_hashes(self, 
                             file_paths: List[Path], 
                             algorithms: List[str],
                             max_workers: int = 4) -> Dict[str, Dict[str, HashResult]]:
        """
        Calcula hashes para múltiplos arquivos em paralelo
        
        Args:
            file_paths: Lista de caminhos de arquivo
            algorithms: Lista de algoritmos
            max_workers: Número máximo de workers
            
        Returns:
            Dicionário aninhado: {arquivo: {algoritmo: resultado}}
        """
        results = {}
        
        if not self.parallel_processing or len(file_paths) == 1:
            # Processamento sequencial
            for file_path in file_paths:
                results[str(file_path)] = self.calculate_multiple_hashes(file_path, algorithms)
        else:
            # Processamento paralelo
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_file = {}
                
                # Submeter tarefas
                for file_path in file_paths:
                    future = executor.submit(self.calculate_multiple_hashes, file_path, algorithms)
                    future_to_file[future] = str(file_path)
                
                # Coletar resultados
                for future in as_completed(future_to_file):
                    file_path = future_to_file[future]
                    try:
                        results[file_path] = future.result()
                    except Exception as e:
                        logger.error(f"Erro no processamento paralelo para {file_path}: {e}")
                        # Criar resultados de erro
                        error_results = {}
                        for algo in algorithms:
                            error_results[algo] = HashResult(
                                algorithm=algo,
                                hash_value="",
                                file_path=file_path,
                                file_size=0,
                                calculation_time=0,
                                error=str(e)
                            )
                        results[file_path] = error_results
        
        return results
    
    def _calculate_empty_file_hash(self, algorithm: str) -> str:
        """Calcula hash para arquivo vazio"""
        hasher = self.SUPPORTED_ALGORITHMS[algorithm]()
        return hasher.hexdigest()
    
    def _calculate_small_file_hash(self, file_path: Path, algorithm: str) -> str:
        """Calcula hash para arquivo pequeno (carrega tudo na memória)"""
        hasher = self.SUPPORTED_ALGORITHMS[algorithm]()
        with open(file_path, 'rb') as f:
            hasher.update(f.read())
        return hasher.hexdigest()
    
    def _calculate_chunked_hash(self, file_path: Path, algorithm: str) -> str:
        """Calcula hash lendo arquivo em chunks"""
        hasher = self.SUPPORTED_ALGORITHMS[algorithm]()
        with open(file_path, 'rb') as f:
            while chunk := f.read(self.chunk_size):
                hasher.update(chunk)
        return hasher.hexdigest()
    
    def _calculate_mmap_hash(self, file_path: Path, algorithm: str) -> str:
        """Calcula hash usando memory mapping"""
        hasher = self.SUPPORTED_ALGORITHMS[algorithm]()
        with open(file_path, 'rb') as f:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                # Processar em chunks mesmo com mmap
                for i in range(0, len(mm), self.chunk_size):
                    chunk = mm[i:i + self.chunk_size]
                    hasher.update(chunk)
        return hasher.hexdigest()
    
    def _calculate_multiple_hashes_single_pass(self, 
                                             file_path: Path, 
                                             algorithms: List[str]) -> Dict[str, str]:
        """Calcula múltiplos hashes em uma única passada pelo arquivo"""
        hashers = {}
        
        # Inicializar hashers
        for algo in algorithms:
            if algo in self.SUPPORTED_ALGORITHMS:
                hashers[algo] = self.SUPPORTED_ALGORITHMS[algo]()
        
        if not hashers:
            return {}
        
        file_size = file_path.stat().st_size
        
        # Escolher estratégia
        if file_size == 0:
            # Arquivo vazio
            return {algo: hasher.hexdigest() for algo, hasher in hashers.items()}
        elif file_size <= self.small_file_limit:
            # Arquivo pequeno - carregar tudo
            with open(file_path, 'rb') as f:
                data = f.read()
                for hasher in hashers.values():
                    hasher.update(data)
        elif self.use_mmap and file_size >= self.mmap_threshold:
            # Arquivo grande - usar mmap
            with open(file_path, 'rb') as f:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    for i in range(0, len(mm), self.chunk_size):
                        chunk = mm[i:i + self.chunk_size]
                        for hasher in hashers.values():
                            hasher.update(chunk)
        else:
            # Arquivo médio - chunks normais
            with open(file_path, 'rb') as f:
                while chunk := f.read(self.chunk_size):
                    for hasher in hashers.values():
                        hasher.update(chunk)
        
        # Retornar hashes finais
        return {algo: hasher.hexdigest() for algo, hasher in hashers.items()}
    
    def verify_hash(self, 
                   file_path: Path, 
                   expected_hash: str, 
                   algorithm: str) -> bool:
        """
        Verifica se hash do arquivo corresponde ao esperado
        
        Args:
            file_path: Caminho do arquivo
            expected_hash: Hash esperado
            algorithm: Algoritmo usado
            
        Returns:
            True se hashes coincidem
        """
        try:
            result = self.calculate_single_hash(file_path, algorithm)
            if result.error:
                logger.error(f"Erro na verificação de hash: {result.error}")
                return False
            
            # Comparação segura contra timing attacks
            return hmac.compare_digest(result.hash_value.lower(), expected_hash.lower())
            
        except Exception as e:
            logger.error(f"Erro na verificação de hash para {file_path}: {e}")
            return False
    
    def get_supported_algorithms(self) -> List[str]:
        """Retorna lista de algoritmos suportados"""
        return list(self.SUPPORTED_ALGORITHMS.keys())
    
    def benchmark_algorithms(self, 
                           file_path: Path, 
                           algorithms: Optional[List[str]] = None) -> Dict[str, float]:
        """
        Faz benchmark dos algoritmos de hash
        
        Args:
            file_path: Arquivo para teste
            algorithms: Algoritmos a testar (None = todos)
            
        Returns:
            Dicionário com tempos de execução
        """
        if algorithms is None:
            algorithms = list(self.SUPPORTED_ALGORITHMS.keys())
        
        benchmarks = {}
        
        for algorithm in algorithms:
            try:
                result = self.calculate_single_hash(file_path, algorithm)
                benchmarks[algorithm] = result.calculation_time
                
                if result.error:
                    logger.warning(f"Erro no benchmark {algorithm}: {result.error}")
                    benchmarks[algorithm] = float('inf')
                    
            except Exception as e:
                logger.error(f"Erro no benchmark {algorithm}: {e}")
                benchmarks[algorithm] = float('inf')
        
        return benchmarks
    
    def get_optimal_chunk_size(self, file_path: Path) -> int:
        """
        Determina tamanho ótimo de chunk baseado no arquivo
        
        Args:
            file_path: Caminho do arquivo
            
        Returns:
            Tamanho ótimo de chunk
        """
        try:
            file_size = file_path.stat().st_size
            
            # Heurística baseada no tamanho do arquivo
            if file_size < 1024 * 1024:  # < 1MB
                return 4096
            elif file_size < 10 * 1024 * 1024:  # < 10MB
                return 8192
            elif file_size < 100 * 1024 * 1024:  # < 100MB
                return 16384
            else:  # >= 100MB
                return 32768
                
        except Exception:
            return self.chunk_size
