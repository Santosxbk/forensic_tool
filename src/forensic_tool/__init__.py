"""
Forensic Tool - Advanced Metadata Analysis

Uma ferramenta completa para análise forense de metadados de arquivos,
oferecendo suporte a múltiplos formatos e interfaces (CLI, Web, API).

Autor: Santos (Refatorado)
Versão: 2.0.0
Licença: MIT
"""

__version__ = "2.0.0"
__author__ = "Santos (Refatorado)"
__email__ = "contato@forensictool.com"
__license__ = "MIT"

# Importações principais
# from .core.analyzer import ForensicAnalyzer  # Removido - não existe mais
from .core.manager import AnalysisManager
from .core.database import ResultsDatabase
from .core.config import Config

# Importações de utilitários
from .utils.hashing import HashCalculator
from .utils.file_utils import FileValidator, FileScanner
from .utils.logger import setup_logger

__all__ = [
    "__version__",
    "__author__",
    "__email__",
    "__license__",
    "AnalysisManager", 
    "ResultsDatabase",
    "Config",
    "HashCalculator",
    "FileValidator",
    "FileScanner",
    "setup_logger",
]
