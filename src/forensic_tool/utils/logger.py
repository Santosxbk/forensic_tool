"""
Sistema de logging avançado para Forensic Tool
"""

import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Optional, Union
from rich.console import Console
from rich.logging import RichHandler
from rich.traceback import install
import colorama
from colorama import Fore, Back, Style

# Instalar rich traceback para melhor visualização de erros
install(show_locals=True)

# Inicializar colorama para Windows
colorama.init(autoreset=True)


class ColoredFormatter(logging.Formatter):
    """Formatter colorido para console"""
    
    COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.RED + Back.WHITE + Style.BRIGHT,
    }
    
    def format(self, record):
        # Aplicar cor baseada no nível
        color = self.COLORS.get(record.levelname, '')
        record.levelname = f"{color}{record.levelname}{Style.RESET_ALL}"
        return super().format(record)


class ForensicLogger:
    """Classe principal para configuração de logging"""
    
    def __init__(self, name: str = "ForensicTool"):
        self.name = name
        self.logger = logging.getLogger(name)
        self.console = Console()
        self._configured = False
    
    def setup(
        self,
        level: Union[str, int] = logging.INFO,
        log_file: Optional[Union[str, Path]] = None,
        max_file_size_mb: int = 10,
        backup_count: int = 5,
        console_output: bool = True,
        rich_console: bool = True,
        format_string: Optional[str] = None
    ) -> logging.Logger:
        """
        Configura o sistema de logging
        
        Args:
            level: Nível de logging (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            log_file: Caminho do arquivo de log
            max_file_size_mb: Tamanho máximo do arquivo de log em MB
            backup_count: Número de arquivos de backup
            console_output: Se deve exibir logs no console
            rich_console: Se deve usar rich para formatação colorida
            format_string: String de formato personalizada
        
        Returns:
            Logger configurado
        """
        if self._configured:
            return self.logger
        
        # Limpar handlers existentes
        self.logger.handlers.clear()
        
        # Definir nível
        if isinstance(level, str):
            level = getattr(logging, level.upper(), logging.INFO)
        self.logger.setLevel(level)
        
        # Formato padrão
        if format_string is None:
            format_string = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        
        # Handler para arquivo
        if log_file:
            self._setup_file_handler(log_file, max_file_size_mb, backup_count, format_string)
        
        # Handler para console
        if console_output:
            self._setup_console_handler(rich_console, format_string)
        
        # Evitar propagação para root logger
        self.logger.propagate = False
        
        self._configured = True
        self.logger.info(f"Sistema de logging configurado - Nível: {logging.getLevelName(level)}")
        
        return self.logger
    
    def _setup_file_handler(
        self, 
        log_file: Union[str, Path], 
        max_size_mb: int, 
        backup_count: int,
        format_string: str
    ) -> None:
        """Configura handler para arquivo com rotação"""
        try:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Handler com rotação
            file_handler = logging.handlers.RotatingFileHandler(
                filename=log_path,
                maxBytes=max_size_mb * 1024 * 1024,
                backupCount=backup_count,
                encoding='utf-8'
            )
            
            # Formatter para arquivo (sem cores)
            file_formatter = logging.Formatter(format_string)
            file_handler.setFormatter(file_formatter)
            
            self.logger.addHandler(file_handler)
            
        except Exception as e:
            print(f"Erro ao configurar logging para arquivo: {e}")
    
    def _setup_console_handler(self, rich_console: bool, format_string: str) -> None:
        """Configura handler para console"""
        try:
            if rich_console:
                # Usar Rich handler para saída colorida avançada
                console_handler = RichHandler(
                    console=self.console,
                    show_time=True,
                    show_level=True,
                    show_path=True,
                    markup=True,
                    rich_tracebacks=True,
                    tracebacks_show_locals=True
                )
                console_handler.setFormatter(logging.Formatter("%(message)s"))
            else:
                # Handler padrão com cores simples
                console_handler = logging.StreamHandler(sys.stdout)
                colored_formatter = ColoredFormatter(format_string)
                console_handler.setFormatter(colored_formatter)
            
            self.logger.addHandler(console_handler)
            
        except Exception as e:
            print(f"Erro ao configurar logging para console: {e}")
    
    def get_logger(self) -> logging.Logger:
        """Retorna o logger configurado"""
        return self.logger
    
    def log_analysis_start(self, analysis_id: str, directory: str, total_files: int) -> None:
        """Log específico para início de análise"""
        self.logger.info(
            f"🔍 [bold green]ANÁLISE INICIADA[/bold green] - "
            f"ID: {analysis_id} | Diretório: {directory} | Arquivos: {total_files}",
            extra={"markup": True}
        )
    
    def log_analysis_progress(self, analysis_id: str, processed: int, total: int, current_file: str = "") -> None:
        """Log específico para progresso de análise"""
        progress = (processed / total) * 100 if total > 0 else 0
        self.logger.info(
            f"📊 [bold blue]PROGRESSO[/bold blue] - "
            f"ID: {analysis_id} | {processed}/{total} ({progress:.1f}%) | {current_file}",
            extra={"markup": True}
        )
    
    def log_analysis_complete(self, analysis_id: str, duration: float, successful: int, failed: int) -> None:
        """Log específico para conclusão de análise"""
        self.logger.info(
            f"✅ [bold green]ANÁLISE CONCLUÍDA[/bold green] - "
            f"ID: {analysis_id} | Duração: {duration:.2f}s | "
            f"Sucessos: {successful} | Falhas: {failed}",
            extra={"markup": True}
        )
    
    def log_file_analysis(self, file_path: str, file_type: str, success: bool, error: str = "") -> None:
        """Log específico para análise de arquivo"""
        if success:
            self.logger.debug(f"✅ Arquivo analisado: {file_path} ({file_type})")
        else:
            self.logger.warning(f"❌ Erro na análise: {file_path} - {error}")
    
    def log_security_event(self, event_type: str, details: str, severity: str = "WARNING") -> None:
        """Log específico para eventos de segurança"""
        level = getattr(logging, severity.upper(), logging.WARNING)
        self.logger.log(
            level,
            f"🛡️ [bold red]SEGURANÇA[/bold red] - {event_type}: {details}",
            extra={"markup": True}
        )
    
    def log_performance_metric(self, metric_name: str, value: Union[int, float], unit: str = "") -> None:
        """Log específico para métricas de performance"""
        self.logger.info(
            f"⚡ [bold yellow]PERFORMANCE[/bold yellow] - "
            f"{metric_name}: {value} {unit}",
            extra={"markup": True}
        )


# Instância global do logger
_global_logger: Optional[ForensicLogger] = None


def setup_logger(
    name: str = "ForensicTool",
    level: Union[str, int] = logging.INFO,
    log_file: Optional[Union[str, Path]] = None,
    max_file_size_mb: int = 10,
    backup_count: int = 5,
    console_output: bool = True,
    rich_console: bool = True,
    format_string: Optional[str] = None
) -> logging.Logger:
    """
    Função principal para configurar logging
    
    Args:
        name: Nome do logger
        level: Nível de logging
        log_file: Arquivo de log
        max_file_size_mb: Tamanho máximo do arquivo
        backup_count: Número de backups
        console_output: Saída no console
        rich_console: Usar Rich para formatação
        format_string: Formato personalizado
    
    Returns:
        Logger configurado
    """
    global _global_logger
    
    if _global_logger is None:
        _global_logger = ForensicLogger(name)
    
    return _global_logger.setup(
        level=level,
        log_file=log_file,
        max_file_size_mb=max_file_size_mb,
        backup_count=backup_count,
        console_output=console_output,
        rich_console=rich_console,
        format_string=format_string
    )


def get_logger(name: str = "ForensicTool") -> logging.Logger:
    """Retorna logger configurado"""
    global _global_logger
    
    if _global_logger is None:
        setup_logger(name)
    
    return _global_logger.get_logger()


def get_forensic_logger() -> ForensicLogger:
    """Retorna instância do ForensicLogger"""
    global _global_logger
    
    if _global_logger is None:
        _global_logger = ForensicLogger()
        _global_logger.setup()
    
    return _global_logger


# Configuração de logging para desenvolvimento
def setup_dev_logging() -> logging.Logger:
    """Configuração rápida para desenvolvimento"""
    return setup_logger(
        level=logging.DEBUG,
        log_file="forensic_dev.log",
        console_output=True,
        rich_console=True
    )


# Configuração de logging para produção
def setup_prod_logging(log_dir: Union[str, Path] = "logs") -> logging.Logger:
    """Configuração para produção"""
    log_path = Path(log_dir) / "forensic_tool.log"
    return setup_logger(
        level=logging.INFO,
        log_file=log_path,
        max_file_size_mb=50,
        backup_count=10,
        console_output=False,
        rich_console=False
    )
