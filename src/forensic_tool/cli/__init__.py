"""
Interface de linha de comando para o Forensic Tool
"""

from .main import main, cli_manager
from .reports import ReportGenerator

__all__ = ['main', 'cli_manager', 'ReportGenerator']
