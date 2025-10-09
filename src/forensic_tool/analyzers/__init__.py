"""
Analisadores especializados para diferentes tipos de arquivo
"""

from .base import BaseAnalyzer, AnalysisResult, AnalyzerRegistry, get_registry
from .image_analyzer import ImageAnalyzer
from .document_analyzer import DocumentAnalyzer
from .media_analyzer import MediaAnalyzer
from .network_analyzer import NetworkAnalyzer
from .security_analyzer import SecurityAnalyzer

# Função para registrar todos os analisadores
def register_all_analyzers() -> AnalyzerRegistry:
    """
    Registra todos os analisadores disponíveis
    
    Returns:
        Registry com todos os analisadores registrados
    """
    registry = get_registry()
    
    # Registrar analisadores
    registry.register(ImageAnalyzer())
    registry.register(DocumentAnalyzer())
    registry.register(MediaAnalyzer())
    registry.register(NetworkAnalyzer())
    registry.register(SecurityAnalyzer())
    
    return registry

__all__ = [
    'BaseAnalyzer',
    'AnalysisResult',
    'AnalyzerRegistry',
    'get_registry',
    'ImageAnalyzer',
    'DocumentAnalyzer', 
    'MediaAnalyzer',
    'NetworkAnalyzer',
    'SecurityAnalyzer',
    'register_all_analyzers',
]
