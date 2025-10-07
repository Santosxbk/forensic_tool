"""
Classe base abstrata para analisadores de arquivos
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Any, Optional, List, Set
from dataclasses import dataclass
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class AnalysisResult:
    """Resultado de análise de arquivo"""
    file_path: str
    file_name: str
    file_size: int
    file_type: str
    analysis_type: str
    metadata: Dict[str, Any]
    success: bool
    error_message: Optional[str] = None
    analysis_duration: float = 0.0
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte resultado para dicionário"""
        return {
            'file_path': self.file_path,
            'file_name': self.file_name,
            'file_size': self.file_size,
            'file_type': self.file_type,
            'analysis_type': self.analysis_type,
            'metadata': self.metadata,
            'success': self.success,
            'error_message': self.error_message,
            'analysis_duration': self.analysis_duration,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }


class BaseAnalyzer(ABC):
    """Classe base abstrata para todos os analisadores"""
    
    def __init__(self, name: str, supported_extensions: Set[str]):
        """
        Inicializa o analisador base
        
        Args:
            name: Nome do analisador
            supported_extensions: Extensões suportadas (com ponto, ex: '.jpg')
        """
        self.name = name
        self.supported_extensions = {ext.lower() for ext in supported_extensions}
        self.logger = logging.getLogger(f"{__name__}.{name}")
    
    def can_analyze(self, file_path: Path) -> bool:
        """
        Verifica se o analisador pode processar o arquivo
        
        Args:
            file_path: Caminho do arquivo
            
        Returns:
            True se pode analisar
        """
        try:
            extension = file_path.suffix.lower()
            return extension in self.supported_extensions
        except Exception as e:
            self.logger.debug(f"Erro ao verificar extensão de {file_path}: {e}")
            return False
    
    def analyze(self, file_path: Path) -> AnalysisResult:
        """
        Analisa um arquivo e retorna resultado
        
        Args:
            file_path: Caminho do arquivo
            
        Returns:
            Resultado da análise
        """
        start_time = datetime.now()
        
        try:
            # Verificações básicas
            if not file_path.exists():
                return self._create_error_result(
                    file_path, "Arquivo não encontrado"
                )
            
            if not file_path.is_file():
                return self._create_error_result(
                    file_path, "Não é um arquivo"
                )
            
            if not self.can_analyze(file_path):
                return self._create_error_result(
                    file_path, f"Extensão não suportada pelo {self.name}"
                )
            
            # Executar análise específica
            metadata = self._analyze_file(file_path)
            
            # Calcular duração
            duration = (datetime.now() - start_time).total_seconds()
            
            # Criar resultado de sucesso
            return AnalysisResult(
                file_path=str(file_path.absolute()),
                file_name=file_path.name,
                file_size=file_path.stat().st_size,
                file_type=self._get_file_type(file_path),
                analysis_type=self.name,
                metadata=metadata,
                success=True,
                analysis_duration=duration,
                timestamp=start_time
            )
            
        except Exception as e:
            self.logger.error(f"Erro na análise de {file_path}: {e}")
            duration = (datetime.now() - start_time).total_seconds()
            
            return AnalysisResult(
                file_path=str(file_path.absolute()),
                file_name=file_path.name if file_path.exists() else "unknown",
                file_size=file_path.stat().st_size if file_path.exists() else 0,
                file_type=self._get_file_type(file_path),
                analysis_type=self.name,
                metadata={},
                success=False,
                error_message=str(e),
                analysis_duration=duration,
                timestamp=start_time
            )
    
    @abstractmethod
    def _analyze_file(self, file_path: Path) -> Dict[str, Any]:
        """
        Método abstrato para análise específica do arquivo
        
        Args:
            file_path: Caminho do arquivo
            
        Returns:
            Dicionário com metadados extraídos
        """
        pass
    
    def _get_file_type(self, file_path: Path) -> str:
        """
        Determina o tipo do arquivo
        
        Args:
            file_path: Caminho do arquivo
            
        Returns:
            Tipo do arquivo
        """
        try:
            extension = file_path.suffix.lower()
            
            # Mapeamento básico de extensões para tipos
            type_mapping = {
                # Imagens
                '.jpg': 'JPEG Image', '.jpeg': 'JPEG Image',
                '.png': 'PNG Image', '.gif': 'GIF Image',
                '.bmp': 'BMP Image', '.tiff': 'TIFF Image', '.tif': 'TIFF Image',
                '.webp': 'WebP Image',
                
                # Documentos
                '.pdf': 'PDF Document',
                '.docx': 'Word Document', '.doc': 'Word Document',
                '.xlsx': 'Excel Spreadsheet', '.xls': 'Excel Spreadsheet',
                '.pptx': 'PowerPoint Presentation', '.ppt': 'PowerPoint Presentation',
                '.txt': 'Text Document', '.rtf': 'Rich Text Document',
                
                # Áudio
                '.mp3': 'MP3 Audio', '.wav': 'WAV Audio',
                '.flac': 'FLAC Audio', '.m4a': 'M4A Audio',
                '.aac': 'AAC Audio', '.ogg': 'OGG Audio',
                
                # Vídeo
                '.mp4': 'MP4 Video', '.avi': 'AVI Video',
                '.mkv': 'MKV Video', '.mov': 'QuickTime Video',
                '.wmv': 'WMV Video', '.flv': 'FLV Video',
                
                # Arquivos
                '.zip': 'ZIP Archive', '.rar': 'RAR Archive',
                '.7z': '7-Zip Archive', '.tar': 'TAR Archive',
                '.gz': 'GZIP Archive'
            }
            
            return type_mapping.get(extension, f"Unknown ({extension})")
            
        except Exception:
            return "Unknown"
    
    def _create_error_result(self, file_path: Path, error_message: str) -> AnalysisResult:
        """
        Cria resultado de erro
        
        Args:
            file_path: Caminho do arquivo
            error_message: Mensagem de erro
            
        Returns:
            Resultado com erro
        """
        return AnalysisResult(
            file_path=str(file_path.absolute()) if file_path else "unknown",
            file_name=file_path.name if file_path and file_path.exists() else "unknown",
            file_size=file_path.stat().st_size if file_path and file_path.exists() else 0,
            file_type=self._get_file_type(file_path) if file_path else "Unknown",
            analysis_type=self.name,
            metadata={},
            success=False,
            error_message=error_message
        )
    
    def get_supported_extensions(self) -> Set[str]:
        """Retorna extensões suportadas"""
        return self.supported_extensions.copy()
    
    def get_name(self) -> str:
        """Retorna nome do analisador"""
        return self.name
    
    def __str__(self) -> str:
        """Representação string do analisador"""
        extensions = ", ".join(sorted(self.supported_extensions))
        return f"{self.name} (extensões: {extensions})"
    
    def __repr__(self) -> str:
        """Representação para debug"""
        return f"{self.__class__.__name__}(name='{self.name}', extensions={self.supported_extensions})"


class MultiFormatAnalyzer(BaseAnalyzer):
    """Analisador que suporta múltiplos formatos com estratégias diferentes"""
    
    def __init__(self, name: str):
        # Será definido pelas subclasses
        super().__init__(name, set())
        self.format_handlers = {}
    
    def add_format_handler(self, extensions: Set[str], handler_func):
        """
        Adiciona handler para extensões específicas
        
        Args:
            extensions: Conjunto de extensões
            handler_func: Função para processar esses formatos
        """
        for ext in extensions:
            ext_lower = ext.lower()
            self.supported_extensions.add(ext_lower)
            self.format_handlers[ext_lower] = handler_func
    
    def _analyze_file(self, file_path: Path) -> Dict[str, Any]:
        """Análise usando handler específico para a extensão"""
        extension = file_path.suffix.lower()
        
        if extension in self.format_handlers:
            handler = self.format_handlers[extension]
            return handler(file_path)
        else:
            raise ValueError(f"Nenhum handler encontrado para extensão: {extension}")


class AnalyzerRegistry:
    """Registro de analisadores disponíveis"""
    
    def __init__(self):
        self._analyzers: List[BaseAnalyzer] = []
        self._extension_map: Dict[str, List[BaseAnalyzer]] = {}
    
    def register(self, analyzer: BaseAnalyzer) -> None:
        """
        Registra um analisador
        
        Args:
            analyzer: Instância do analisador
        """
        if analyzer not in self._analyzers:
            self._analyzers.append(analyzer)
            
            # Atualizar mapa de extensões
            for ext in analyzer.get_supported_extensions():
                if ext not in self._extension_map:
                    self._extension_map[ext] = []
                self._extension_map[ext].append(analyzer)
    
    def get_analyzer_for_file(self, file_path: Path) -> Optional[BaseAnalyzer]:
        """
        Encontra analisador apropriado para arquivo
        
        Args:
            file_path: Caminho do arquivo
            
        Returns:
            Analisador apropriado ou None
        """
        extension = file_path.suffix.lower()
        analyzers = self._extension_map.get(extension, [])
        
        # Retornar primeiro analisador que pode processar
        for analyzer in analyzers:
            if analyzer.can_analyze(file_path):
                return analyzer
        
        return None
    
    def get_all_analyzers(self) -> List[BaseAnalyzer]:
        """Retorna todos os analisadores registrados"""
        return self._analyzers.copy()
    
    def get_supported_extensions(self) -> Set[str]:
        """Retorna todas as extensões suportadas"""
        return set(self._extension_map.keys())
    
    def get_analyzers_by_type(self, analyzer_type: str) -> List[BaseAnalyzer]:
        """
        Retorna analisadores por tipo
        
        Args:
            analyzer_type: Tipo do analisador
            
        Returns:
            Lista de analisadores do tipo especificado
        """
        return [a for a in self._analyzers if a.name == analyzer_type]


# Instância global do registro
_global_registry: Optional[AnalyzerRegistry] = None


def get_registry() -> AnalyzerRegistry:
    """Retorna registro global de analisadores"""
    global _global_registry
    if _global_registry is None:
        _global_registry = AnalyzerRegistry()
    return _global_registry
