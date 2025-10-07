"""
Sistema de configuração centralizado para Forensic Tool
"""

import os
import yaml
import json
from pathlib import Path
from typing import Dict, Any, Optional, Union
from dataclasses import dataclass, asdict
import logging

logger = logging.getLogger(__name__)


@dataclass
class DatabaseConfig:
    """Configurações do banco de dados"""
    path: str = "forensic_results.db"
    timeout: int = 30
    check_same_thread: bool = False


@dataclass
class AnalysisConfig:
    """Configurações de análise"""
    max_file_size_mb: int = 1024
    max_files_per_analysis: int = 50000
    thread_count: int = 4
    chunk_size: int = 8192
    hash_algorithms: list = None
    supported_extensions: dict = None
    
    def __post_init__(self):
        if self.hash_algorithms is None:
            self.hash_algorithms = ['md5', 'sha1', 'sha256', 'sha512']
        
        if self.supported_extensions is None:
            self.supported_extensions = {
                'IMAGENS': ['.jpg', '.jpeg', '.png', '.bmp', '.gif', '.tiff', '.tif', '.webp'],
                'PDF': ['.pdf'],
                'DOCUMENTOS': ['.docx', '.doc', '.xlsx', '.xls', '.pptx', '.ppt', '.txt', '.rtf'],
                'AUDIO': ['.mp3', '.flac', '.wav', '.m4a', '.aac', '.ogg', '.wma'],
                'VIDEO': ['.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv', '.webm'],
                'ARQUIVOS': ['.zip', '.rar', '.7z', '.tar', '.gz']
            }


@dataclass
class WebConfig:
    """Configurações do servidor web"""
    host: str = "localhost"
    port: int = 8000
    debug: bool = False
    auto_open_browser: bool = True
    cors_origins: list = None
    auth_required: bool = False
    auth_token_file: str = "forensic_tokens.txt"
    max_upload_size_mb: int = 500
    
    def __post_init__(self):
        if self.cors_origins is None:
            self.cors_origins = [
                "http://localhost:8000",
                "http://127.0.0.1:8000"
            ]


@dataclass
class LoggingConfig:
    """Configurações de logging"""
    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    file_path: str = "forensic_tool.log"
    max_file_size_mb: int = 10
    backup_count: int = 5
    console_output: bool = True


@dataclass
class SecurityConfig:
    """Configurações de segurança"""
    validate_file_paths: bool = True
    allow_symlinks: bool = False
    max_path_depth: int = 20
    blocked_extensions: list = None
    scan_archives: bool = True
    
    def __post_init__(self):
        if self.blocked_extensions is None:
            self.blocked_extensions = ['.exe', '.bat', '.cmd', '.scr', '.com']


class Config:
    """Classe principal de configuração"""
    
    def __init__(self, config_file: Optional[Union[str, Path]] = None):
        self.config_file = Path(config_file) if config_file else None
        
        # Configurações padrão
        self.database = DatabaseConfig()
        self.analysis = AnalysisConfig()
        self.web = WebConfig()
        self.logging = LoggingConfig()
        self.security = SecurityConfig()
        
        # Carregar configurações se arquivo fornecido
        if self.config_file and self.config_file.exists():
            self.load_from_file()
        
        # Carregar variáveis de ambiente
        self.load_from_env()
    
    def load_from_file(self) -> None:
        """Carrega configurações de arquivo YAML ou JSON"""
        try:
            if not self.config_file.exists():
                logger.warning(f"Arquivo de configuração não encontrado: {self.config_file}")
                return
            
            with open(self.config_file, 'r', encoding='utf-8') as f:
                if self.config_file.suffix.lower() in ['.yaml', '.yml']:
                    data = yaml.safe_load(f)
                elif self.config_file.suffix.lower() == '.json':
                    data = json.load(f)
                else:
                    logger.error(f"Formato de arquivo não suportado: {self.config_file.suffix}")
                    return
            
            # Atualizar configurações
            if 'database' in data:
                self._update_config(self.database, data['database'])
            
            if 'analysis' in data:
                self._update_config(self.analysis, data['analysis'])
            
            if 'web' in data:
                self._update_config(self.web, data['web'])
            
            if 'logging' in data:
                self._update_config(self.logging, data['logging'])
            
            if 'security' in data:
                self._update_config(self.security, data['security'])
            
            logger.info(f"Configurações carregadas de: {self.config_file}")
            
        except Exception as e:
            logger.error(f"Erro ao carregar configurações: {e}")
    
    def load_from_env(self) -> None:
        """Carrega configurações de variáveis de ambiente"""
        # Database
        if os.getenv('FORENSIC_DB_PATH'):
            self.database.path = os.getenv('FORENSIC_DB_PATH')
        
        # Analysis
        if os.getenv('FORENSIC_MAX_FILE_SIZE'):
            try:
                self.analysis.max_file_size_mb = int(os.getenv('FORENSIC_MAX_FILE_SIZE'))
            except ValueError:
                pass
        
        if os.getenv('FORENSIC_THREAD_COUNT'):
            try:
                self.analysis.thread_count = int(os.getenv('FORENSIC_THREAD_COUNT'))
            except ValueError:
                pass
        
        # Web
        if os.getenv('FORENSIC_WEB_HOST'):
            self.web.host = os.getenv('FORENSIC_WEB_HOST')
        
        if os.getenv('FORENSIC_WEB_PORT'):
            try:
                self.web.port = int(os.getenv('FORENSIC_WEB_PORT'))
            except ValueError:
                pass
        
        if os.getenv('FORENSIC_AUTH_TOKEN'):
            self.web.auth_required = True
        
        # Logging
        if os.getenv('FORENSIC_LOG_LEVEL'):
            self.logging.level = os.getenv('FORENSIC_LOG_LEVEL').upper()
        
        if os.getenv('FORENSIC_LOG_FILE'):
            self.logging.file_path = os.getenv('FORENSIC_LOG_FILE')
    
    def save_to_file(self, file_path: Optional[Union[str, Path]] = None) -> None:
        """Salva configurações em arquivo YAML"""
        target_file = Path(file_path) if file_path else self.config_file
        
        if not target_file:
            target_file = Path("forensic_config.yaml")
        
        try:
            config_data = {
                'database': asdict(self.database),
                'analysis': asdict(self.analysis),
                'web': asdict(self.web),
                'logging': asdict(self.logging),
                'security': asdict(self.security)
            }
            
            target_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(target_file, 'w', encoding='utf-8') as f:
                yaml.dump(config_data, f, default_flow_style=False, 
                         allow_unicode=True, indent=2)
            
            logger.info(f"Configurações salvas em: {target_file}")
            
        except Exception as e:
            logger.error(f"Erro ao salvar configurações: {e}")
    
    def _update_config(self, config_obj: object, data: Dict[str, Any]) -> None:
        """Atualiza objeto de configuração com dados"""
        for key, value in data.items():
            if hasattr(config_obj, key):
                setattr(config_obj, key, value)
    
    def get_supported_extensions(self) -> set:
        """Retorna conjunto de extensões suportadas"""
        extensions = set()
        for ext_list in self.analysis.supported_extensions.values():
            extensions.update(ext_list)
        return extensions
    
    def is_extension_supported(self, extension: str) -> bool:
        """Verifica se extensão é suportada"""
        return extension.lower() in self.get_supported_extensions()
    
    def is_extension_blocked(self, extension: str) -> bool:
        """Verifica se extensão está bloqueada"""
        return extension.lower() in self.security.blocked_extensions
    
    def validate(self) -> bool:
        """Valida configurações"""
        try:
            # Validar configurações básicas
            if self.analysis.max_file_size_mb <= 0:
                logger.error("Tamanho máximo de arquivo deve ser maior que 0")
                return False
            
            if self.analysis.thread_count <= 0:
                logger.error("Número de threads deve ser maior que 0")
                return False
            
            if not (1 <= self.web.port <= 65535):
                logger.error("Porta deve estar entre 1 e 65535")
                return False
            
            # Validar nível de logging
            valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
            if self.logging.level.upper() not in valid_levels:
                logger.error(f"Nível de logging inválido: {self.logging.level}")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Erro na validação de configurações: {e}")
            return False
    
    def __str__(self) -> str:
        """Representação string das configurações"""
        return f"""Forensic Tool Configuration:
Database: {self.database.path}
Analysis: {self.analysis.thread_count} threads, max {self.analysis.max_file_size_mb}MB
Web: {self.web.host}:{self.web.port} (auth: {self.web.auth_required})
Logging: {self.logging.level} -> {self.logging.file_path}
Security: Path validation: {self.security.validate_file_paths}"""


# Instância global de configuração
_global_config: Optional[Config] = None


def get_config() -> Config:
    """Retorna instância global de configuração"""
    global _global_config
    if _global_config is None:
        _global_config = Config()
    return _global_config


def set_config(config: Config) -> None:
    """Define instância global de configuração"""
    global _global_config
    _global_config = config


def load_config(config_file: Union[str, Path]) -> Config:
    """Carrega e define configuração global"""
    config = Config(config_file)
    set_config(config)
    return config
