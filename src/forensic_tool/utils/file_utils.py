"""
Utilitários para validação e escaneamento de arquivos
"""

import os
import mimetypes
from pathlib import Path
from typing import Generator, List, Set, Optional, Tuple, Dict, Any
import logging
import magic
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import stat

logger = logging.getLogger(__name__)


class FileValidator:
    """Validador de arquivos e caminhos"""
    
    def __init__(self, 
                 max_path_depth: int = 20,
                 allow_symlinks: bool = False,
                 blocked_extensions: Optional[Set[str]] = None,
                 max_file_size_mb: int = 1024):
        """
        Inicializa o validador
        
        Args:
            max_path_depth: Profundidade máxima de diretórios
            allow_symlinks: Se permite seguir links simbólicos
            blocked_extensions: Extensões bloqueadas
            max_file_size_mb: Tamanho máximo de arquivo em MB
        """
        self.max_path_depth = max_path_depth
        self.allow_symlinks = allow_symlinks
        self.blocked_extensions = blocked_extensions or {'.exe', '.bat', '.cmd', '.scr', '.com'}
        self.max_file_size_bytes = max_file_size_mb * 1024 * 1024
        
        # Inicializar detector MIME
        try:
            self.mime_detector = magic.Magic(mime=True)
        except Exception as e:
            logger.warning(f"Magic não disponível: {e}")
            self.mime_detector = None
    
    def validate_path(self, path: Path) -> Tuple[bool, str]:
        """
        Valida um caminho de arquivo ou diretório
        
        Args:
            path: Caminho a ser validado
            
        Returns:
            Tuple (é_válido, mensagem_erro)
        """
        try:
            # Resolver caminho absoluto
            abs_path = path.resolve()
            
            # Verificar se existe
            if not abs_path.exists():
                return False, f"Caminho não existe: {path}"
            
            # Verificar profundidade
            parts = abs_path.parts
            if len(parts) > self.max_path_depth:
                return False, f"Caminho muito profundo (>{self.max_path_depth} níveis)"
            
            # Verificar links simbólicos
            if abs_path.is_symlink() and not self.allow_symlinks:
                return False, "Links simbólicos não são permitidos"
            
            # Verificar permissões de leitura
            if not os.access(abs_path, os.R_OK):
                return False, "Sem permissão de leitura"
            
            return True, ""
            
        except Exception as e:
            return False, f"Erro na validação: {e}"
    
    def validate_file(self, file_path: Path) -> Tuple[bool, str]:
        """
        Valida um arquivo específico
        
        Args:
            file_path: Caminho do arquivo
            
        Returns:
            Tuple (é_válido, mensagem_erro)
        """
        # Validação básica de caminho
        is_valid, error = self.validate_path(file_path)
        if not is_valid:
            return False, error
        
        try:
            # Verificar se é arquivo
            if not file_path.is_file():
                return False, "Não é um arquivo"
            
            # Verificar extensão bloqueada
            extension = file_path.suffix.lower()
            if extension in self.blocked_extensions:
                return False, f"Extensão bloqueada: {extension}"
            
            # Verificar tamanho
            file_size = file_path.stat().st_size
            if file_size > self.max_file_size_bytes:
                size_mb = file_size / (1024 * 1024)
                max_mb = self.max_file_size_bytes / (1024 * 1024)
                return False, f"Arquivo muito grande: {size_mb:.1f}MB (max: {max_mb}MB)"
            
            # Verificar se arquivo está vazio
            if file_size == 0:
                return False, "Arquivo vazio"
            
            return True, ""
            
        except Exception as e:
            return False, f"Erro na validação do arquivo: {e}"
    
    def is_supported_extension(self, extension: str, supported_extensions: Set[str]) -> bool:
        """Verifica se extensão é suportada"""
        return extension.lower() in supported_extensions
    
    def detect_mime_type(self, file_path: Path) -> Optional[str]:
        """
        Detecta tipo MIME do arquivo
        
        Args:
            file_path: Caminho do arquivo
            
        Returns:
            Tipo MIME ou None se não detectado
        """
        try:
            # Tentar com python-magic primeiro
            if self.mime_detector:
                return self.mime_detector.from_file(str(file_path))
            
            # Fallback para mimetypes
            mime_type, _ = mimetypes.guess_type(str(file_path))
            return mime_type
            
        except Exception as e:
            logger.debug(f"Erro ao detectar MIME type para {file_path}: {e}")
            return None
    
    def get_file_info(self, file_path: Path) -> Dict[str, Any]:
        """
        Obtém informações básicas do arquivo
        
        Args:
            file_path: Caminho do arquivo
            
        Returns:
            Dicionário com informações do arquivo
        """
        try:
            stat_info = file_path.stat()
            
            return {
                'name': file_path.name,
                'path': str(file_path.absolute()),
                'size_bytes': stat_info.st_size,
                'size_mb': stat_info.st_size / (1024 * 1024),
                'extension': file_path.suffix.lower(),
                'modified_time': stat_info.st_mtime,
                'created_time': stat_info.st_ctime,
                'permissions': oct(stat_info.st_mode)[-3:],
                'mime_type': self.detect_mime_type(file_path),
                'is_readable': os.access(file_path, os.R_OK),
                'is_writable': os.access(file_path, os.W_OK),
            }
            
        except Exception as e:
            logger.error(f"Erro ao obter informações do arquivo {file_path}: {e}")
            return {}


class FileScanner:
    """Scanner de arquivos em diretórios"""
    
    def __init__(self, 
                 validator: Optional[FileValidator] = None,
                 supported_extensions: Optional[Set[str]] = None):
        """
        Inicializa o scanner
        
        Args:
            validator: Validador de arquivos
            supported_extensions: Extensões suportadas
        """
        self.validator = validator or FileValidator()
        self.supported_extensions = supported_extensions or set()
    
    def scan_directory(self, 
                      directory: Path, 
                      recursive: bool = True,
                      max_files: int = 50000) -> Generator[Path, None, None]:
        """
        Escaneia diretório em busca de arquivos suportados
        
        Args:
            directory: Diretório a ser escaneado
            recursive: Se deve escanear recursivamente
            max_files: Número máximo de arquivos a retornar
            
        Yields:
            Caminhos de arquivos válidos
        """
        count = 0
        
        try:
            # Validar diretório
            is_valid, error = self.validator.validate_path(directory)
            if not is_valid:
                logger.error(f"Diretório inválido: {error}")
                return
            
            # Escolher método de busca
            if recursive:
                pattern = "**/*"
            else:
                pattern = "*"
            
            # Escanear arquivos
            for file_path in directory.glob(pattern):
                if count >= max_files:
                    logger.warning(f"Limite de arquivos atingido: {max_files}")
                    break
                
                # Verificar se é arquivo
                if not file_path.is_file():
                    continue
                
                # Validar arquivo
                is_valid, error = self.validator.validate_file(file_path)
                if not is_valid:
                    logger.debug(f"Arquivo inválido {file_path}: {error}")
                    continue
                
                # Verificar extensão suportada
                if self.supported_extensions:
                    extension = file_path.suffix.lower()
                    if not self.validator.is_supported_extension(extension, self.supported_extensions):
                        continue
                
                yield file_path
                count += 1
                
        except Exception as e:
            logger.error(f"Erro ao escanear diretório {directory}: {e}")
    
    def count_files(self, 
                   directory: Path, 
                   recursive: bool = True,
                   max_count: int = 100000) -> int:
        """
        Conta arquivos suportados no diretório
        
        Args:
            directory: Diretório a ser contado
            recursive: Se deve contar recursivamente
            max_count: Contagem máxima (para evitar travamento)
            
        Returns:
            Número de arquivos suportados
        """
        count = 0
        
        try:
            for _ in self.scan_directory(directory, recursive, max_count):
                count += 1
                if count >= max_count:
                    break
                    
        except Exception as e:
            logger.error(f"Erro ao contar arquivos em {directory}: {e}")
        
        return count
    
    def get_file_statistics(self, directory: Path) -> Dict[str, Any]:
        """
        Obtém estatísticas dos arquivos no diretório
        
        Args:
            directory: Diretório a ser analisado
            
        Returns:
            Dicionário com estatísticas
        """
        stats = {
            'total_files': 0,
            'total_size_bytes': 0,
            'total_size_mb': 0,
            'extensions': {},
            'mime_types': {},
            'largest_file': {'path': '', 'size': 0},
            'smallest_file': {'path': '', 'size': float('inf')},
        }
        
        try:
            for file_path in self.scan_directory(directory):
                file_info = self.validator.get_file_info(file_path)
                
                if not file_info:
                    continue
                
                # Atualizar contadores
                stats['total_files'] += 1
                stats['total_size_bytes'] += file_info['size_bytes']
                
                # Contadores por extensão
                ext = file_info['extension']
                stats['extensions'][ext] = stats['extensions'].get(ext, 0) + 1
                
                # Contadores por MIME type
                mime = file_info.get('mime_type', 'unknown')
                stats['mime_types'][mime] = stats['mime_types'].get(mime, 0) + 1
                
                # Maior arquivo
                if file_info['size_bytes'] > stats['largest_file']['size']:
                    stats['largest_file'] = {
                        'path': file_info['path'],
                        'size': file_info['size_bytes']
                    }
                
                # Menor arquivo
                if file_info['size_bytes'] < stats['smallest_file']['size']:
                    stats['smallest_file'] = {
                        'path': file_info['path'],
                        'size': file_info['size_bytes']
                    }
            
            # Calcular tamanho total em MB
            stats['total_size_mb'] = stats['total_size_bytes'] / (1024 * 1024)
            
            # Limpar menor arquivo se não encontrou nenhum
            if stats['smallest_file']['size'] == float('inf'):
                stats['smallest_file'] = {'path': '', 'size': 0}
                
        except Exception as e:
            logger.error(f"Erro ao calcular estatísticas para {directory}: {e}")
        
        return stats
    
    def find_duplicates(self, 
                       directory: Path, 
                       hash_algorithm: str = 'md5') -> Dict[str, List[str]]:
        """
        Encontra arquivos duplicados baseado em hash
        
        Args:
            directory: Diretório a ser analisado
            hash_algorithm: Algoritmo de hash a usar
            
        Returns:
            Dicionário com hash como chave e lista de caminhos como valor
        """
        duplicates = {}
        hash_to_files = {}
        
        def calculate_hash(file_path: Path) -> Optional[str]:
            """Calcula hash do arquivo"""
            try:
                hasher = hashlib.new(hash_algorithm)
                with open(file_path, 'rb') as f:
                    for chunk in iter(lambda: f.read(8192), b""):
                        hasher.update(chunk)
                return hasher.hexdigest()
            except Exception as e:
                logger.debug(f"Erro ao calcular hash para {file_path}: {e}")
                return None
        
        try:
            # Usar ThreadPoolExecutor para calcular hashes em paralelo
            with ThreadPoolExecutor(max_workers=4) as executor:
                future_to_file = {}
                
                # Submeter tarefas
                for file_path in self.scan_directory(directory):
                    # Só calcular hash para arquivos pequenos/médios
                    if file_path.stat().st_size <= 100 * 1024 * 1024:  # 100MB
                        future = executor.submit(calculate_hash, file_path)
                        future_to_file[future] = file_path
                
                # Coletar resultados
                for future in as_completed(future_to_file):
                    file_path = future_to_file[future]
                    try:
                        file_hash = future.result()
                        if file_hash:
                            if file_hash not in hash_to_files:
                                hash_to_files[file_hash] = []
                            hash_to_files[file_hash].append(str(file_path))
                    except Exception as e:
                        logger.debug(f"Erro ao processar {file_path}: {e}")
            
            # Filtrar apenas duplicatas
            for file_hash, file_paths in hash_to_files.items():
                if len(file_paths) > 1:
                    duplicates[file_hash] = file_paths
                    
        except Exception as e:
            logger.error(f"Erro ao encontrar duplicatas em {directory}: {e}")
        
        return duplicates
