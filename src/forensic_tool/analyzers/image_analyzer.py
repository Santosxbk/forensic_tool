"""
Analisador especializado para imagens
"""

from pathlib import Path
from typing import Dict, Any, Optional, Tuple
import logging
from datetime import datetime
from .base import BaseAnalyzer

# Importações condicionais
try:
    from PIL import Image, ExifTags
    from PIL.ExifTags import TAGS, GPSTAGS
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

try:
    import cv2
    CV2_AVAILABLE = True
except ImportError:
    CV2_AVAILABLE = False

logger = logging.getLogger(__name__)


class ImageAnalyzer(BaseAnalyzer):
    """Analisador avançado para imagens"""
    
    SUPPORTED_EXTENSIONS = {
        '.jpg', '.jpeg', '.png', '.bmp', '.gif', 
        '.tiff', '.tif', '.webp', '.ico', '.psd'
    }
    
    def __init__(self):
        super().__init__("ImageAnalyzer", self.SUPPORTED_EXTENSIONS)
        
        if not PIL_AVAILABLE:
            logger.warning("PIL/Pillow não disponível - funcionalidade limitada")
        
        if not CV2_AVAILABLE:
            logger.warning("OpenCV não disponível - análise avançada desabilitada")
    
    def _analyze_file(self, file_path: Path) -> Dict[str, Any]:
        """Análise específica para imagens"""
        metadata = {
            'format': 'unknown',
            'dimensions': {'width': 0, 'height': 0},
            'color_mode': 'unknown',
            'has_exif': False,
            'exif_data': {},
            'gps_data': {},
            'camera_info': {},
            'technical_info': {},
            'color_analysis': {},
            'quality_metrics': {}
        }
        
        try:
            # Análise básica com PIL
            if PIL_AVAILABLE:
                metadata.update(self._analyze_with_pil(file_path))
            
            # Análise avançada com OpenCV
            if CV2_AVAILABLE:
                metadata.update(self._analyze_with_opencv(file_path))
            
            # Análise de qualidade
            metadata['quality_metrics'] = self._analyze_quality(file_path)
            
        except Exception as e:
            logger.error(f"Erro na análise de imagem {file_path}: {e}")
            metadata['analysis_error'] = str(e)
        
        return metadata
    
    def _analyze_with_pil(self, file_path: Path) -> Dict[str, Any]:
        """Análise usando PIL/Pillow"""
        metadata = {}
        
        try:
            with Image.open(file_path) as img:
                # Informações básicas
                metadata['format'] = img.format or 'unknown'
                metadata['dimensions'] = {
                    'width': img.size[0],
                    'height': img.size[1]
                }
                metadata['color_mode'] = img.mode
                metadata['has_transparency'] = 'transparency' in img.info
                
                # Informações adicionais
                if hasattr(img, 'info') and img.info:
                    metadata['image_info'] = self._clean_image_info(img.info)
                
                # Análise EXIF
                exif_data = self._extract_exif_data(img)
                if exif_data:
                    metadata['has_exif'] = True
                    metadata['exif_data'] = exif_data['exif']
                    metadata['gps_data'] = exif_data['gps']
                    metadata['camera_info'] = exif_data['camera']
                    metadata['technical_info'] = exif_data['technical']
                
                # Análise de cores
                metadata['color_analysis'] = self._analyze_colors(img)
                
        except Exception as e:
            logger.error(f"Erro na análise PIL para {file_path}: {e}")
            metadata['pil_error'] = str(e)
        
        return metadata
    
    def _analyze_with_opencv(self, file_path: Path) -> Dict[str, Any]:
        """Análise usando OpenCV"""
        metadata = {}
        
        try:
            # Carregar imagem
            img = cv2.imread(str(file_path), cv2.IMREAD_UNCHANGED)
            
            if img is not None:
                # Informações da imagem
                if len(img.shape) == 3:
                    height, width, channels = img.shape
                    metadata['opencv_channels'] = channels
                else:
                    height, width = img.shape
                    metadata['opencv_channels'] = 1
                
                metadata['opencv_dimensions'] = {
                    'width': width,
                    'height': height
                }
                
                # Análise de histograma
                metadata['histogram_analysis'] = self._analyze_histogram(img)
                
                # Detecção de bordas
                metadata['edge_analysis'] = self._analyze_edges(img)
                
                # Análise de nitidez
                metadata['sharpness_score'] = self._calculate_sharpness(img)
                
        except Exception as e:
            logger.error(f"Erro na análise OpenCV para {file_path}: {e}")
            metadata['opencv_error'] = str(e)
        
        return metadata
    
    def _extract_exif_data(self, img: Image.Image) -> Optional[Dict[str, Any]]:
        """Extrai dados EXIF da imagem"""
        try:
            exif_dict = img._getexif()
            if not exif_dict:
                return None
            
            result = {
                'exif': {},
                'gps': {},
                'camera': {},
                'technical': {}
            }
            
            for tag_id, value in exif_dict.items():
                tag_name = TAGS.get(tag_id, tag_id)
                
                try:
                    # Processar valor
                    processed_value = self._process_exif_value(value)
                    
                    # Categorizar dados
                    if tag_name == 'GPSInfo':
                        result['gps'] = self._process_gps_data(value)
                    elif tag_name in ['Make', 'Model', 'Software']:
                        result['camera'][tag_name] = processed_value
                    elif tag_name in ['DateTime', 'DateTimeOriginal', 'DateTimeDigitized']:
                        result['technical'][tag_name] = processed_value
                    elif tag_name in ['ExposureTime', 'FNumber', 'ISO', 'FocalLength']:
                        result['technical'][tag_name] = processed_value
                    else:
                        result['exif'][tag_name] = processed_value
                        
                except Exception as e:
                    logger.debug(f"Erro ao processar tag EXIF {tag_name}: {e}")
                    result['exif'][tag_name] = str(value)
            
            return result
            
        except Exception as e:
            logger.debug(f"Erro na extração EXIF: {e}")
            return None
    
    def _process_gps_data(self, gps_info: Dict) -> Dict[str, Any]:
        """Processa dados GPS do EXIF"""
        gps_data = {}
        
        try:
            for key, value in gps_info.items():
                tag_name = GPSTAGS.get(key, key)
                gps_data[tag_name] = self._process_exif_value(value)
            
            # Converter coordenadas se disponíveis
            if 'GPSLatitude' in gps_data and 'GPSLongitude' in gps_data:
                lat = self._convert_gps_coordinate(
                    gps_data['GPSLatitude'], 
                    gps_data.get('GPSLatitudeRef', 'N')
                )
                lon = self._convert_gps_coordinate(
                    gps_data['GPSLongitude'], 
                    gps_data.get('GPSLongitudeRef', 'E')
                )
                
                if lat is not None and lon is not None:
                    gps_data['decimal_coordinates'] = {
                        'latitude': lat,
                        'longitude': lon
                    }
                    
        except Exception as e:
            logger.debug(f"Erro no processamento GPS: {e}")
        
        return gps_data
    
    def _convert_gps_coordinate(self, coord_tuple: tuple, ref: str) -> Optional[float]:
        """Converte coordenada GPS para decimal"""
        try:
            if not coord_tuple or len(coord_tuple) != 3:
                return None
            
            degrees = float(coord_tuple[0])
            minutes = float(coord_tuple[1])
            seconds = float(coord_tuple[2])
            
            decimal = degrees + (minutes / 60.0) + (seconds / 3600.0)
            
            if ref in ['S', 'W']:
                decimal = -decimal
            
            return decimal
            
        except Exception as e:
            logger.debug(f"Erro na conversão GPS: {e}")
            return None
    
    def _process_exif_value(self, value: Any) -> Any:
        """Processa valor EXIF para serialização"""
        try:
            if isinstance(value, (str, int, float, bool)):
                return value
            elif isinstance(value, bytes):
                try:
                    return value.decode('utf-8', errors='ignore')
                except:
                    return f"<bytes:{len(value)}>"
            elif isinstance(value, (tuple, list)):
                return [self._process_exif_value(v) for v in value]
            else:
                return str(value)
        except:
            return str(value)
    
    def _clean_image_info(self, info: Dict) -> Dict[str, Any]:
        """Limpa informações da imagem para serialização"""
        cleaned = {}
        for key, value in info.items():
            try:
                if isinstance(value, (str, int, float, bool)):
                    cleaned[key] = value
                else:
                    cleaned[key] = str(value)
            except:
                cleaned[key] = f"<{type(value).__name__}>"
        return cleaned
    
    def _analyze_colors(self, img: Image.Image) -> Dict[str, Any]:
        """Análise de cores da imagem"""
        color_info = {}
        
        try:
            # Informações básicas de cor
            color_info['mode'] = img.mode
            color_info['has_palette'] = hasattr(img, 'palette') and img.palette is not None
            
            # Análise de cores dominantes (simplificada)
            if img.mode in ['RGB', 'RGBA']:
                # Reduzir imagem para análise mais rápida
                small_img = img.resize((50, 50))
                colors = small_img.getcolors(maxcolors=256*256*256)
                
                if colors:
                    # Cores mais frequentes
                    colors.sort(key=lambda x: x[0], reverse=True)
                    dominant_colors = []
                    
                    for count, color in colors[:5]:  # Top 5
                        if isinstance(color, (tuple, list)) and len(color) >= 3:
                            dominant_colors.append({
                                'color': color[:3],  # RGB
                                'frequency': count,
                                'percentage': (count / (50*50)) * 100
                            })
                    
                    color_info['dominant_colors'] = dominant_colors
                    
        except Exception as e:
            logger.debug(f"Erro na análise de cores: {e}")
            color_info['analysis_error'] = str(e)
        
        return color_info
    
    def _analyze_histogram(self, img) -> Dict[str, Any]:
        """Análise de histograma usando OpenCV"""
        if not CV2_AVAILABLE:
            return {}
        
        try:
            import numpy as np
            
            hist_data = {}
            
            if len(img.shape) == 3:
                # Imagem colorida
                colors = ['blue', 'green', 'red']
                for i, color in enumerate(colors):
                    hist = cv2.calcHist([img], [i], None, [256], [0, 256])
                    hist_data[f'{color}_histogram'] = {
                        'mean': float(np.mean(hist)),
                        'std': float(np.std(hist)),
                        'max': float(np.max(hist)),
                        'min': float(np.min(hist))
                    }
            else:
                # Imagem em escala de cinza
                hist = cv2.calcHist([img], [0], None, [256], [0, 256])
                hist_data['gray_histogram'] = {
                    'mean': float(np.mean(hist)),
                    'std': float(np.std(hist)),
                    'max': float(np.max(hist)),
                    'min': float(np.min(hist))
                }
            
            return hist_data
            
        except Exception as e:
            logger.debug(f"Erro na análise de histograma: {e}")
            return {'histogram_error': str(e)}
    
    def _analyze_edges(self, img) -> Dict[str, Any]:
        """Análise de bordas usando OpenCV"""
        if not CV2_AVAILABLE:
            return {}
        
        try:
            import numpy as np
            
            # Converter para escala de cinza se necessário
            if len(img.shape) == 3:
                gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            else:
                gray = img
            
            # Detectar bordas com Canny
            edges = cv2.Canny(gray, 50, 150)
            
            # Calcular estatísticas
            total_pixels = edges.shape[0] * edges.shape[1]
            edge_pixels = np.count_nonzero(edges)
            edge_percentage = (edge_pixels / total_pixels) * 100
            
            return {
                'edge_pixels': int(edge_pixels),
                'total_pixels': int(total_pixels),
                'edge_percentage': float(edge_percentage),
                'edge_density': 'high' if edge_percentage > 10 else 'medium' if edge_percentage > 5 else 'low'
            }
            
        except Exception as e:
            logger.debug(f"Erro na análise de bordas: {e}")
            return {'edge_analysis_error': str(e)}
    
    def _calculate_sharpness(self, img) -> float:
        """Calcula score de nitidez da imagem"""
        if not CV2_AVAILABLE:
            return 0.0
        
        try:
            import numpy as np
            
            # Converter para escala de cinza se necessário
            if len(img.shape) == 3:
                gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            else:
                gray = img
            
            # Calcular variância do Laplaciano
            laplacian_var = cv2.Laplacian(gray, cv2.CV_64F).var()
            
            return float(laplacian_var)
            
        except Exception as e:
            logger.debug(f"Erro no cálculo de nitidez: {e}")
            return 0.0
    
    def _analyze_quality(self, file_path: Path) -> Dict[str, Any]:
        """Análise de qualidade da imagem"""
        quality_metrics = {
            'file_size_mb': 0.0,
            'compression_ratio': 0.0,
            'estimated_quality': 'unknown'
        }
        
        try:
            # Tamanho do arquivo
            file_size = file_path.stat().st_size
            quality_metrics['file_size_mb'] = file_size / (1024 * 1024)
            
            # Estimativa de qualidade baseada em tamanho e dimensões
            if PIL_AVAILABLE:
                with Image.open(file_path) as img:
                    width, height = img.size
                    total_pixels = width * height
                    
                    if total_pixels > 0:
                        bytes_per_pixel = file_size / total_pixels
                        quality_metrics['bytes_per_pixel'] = bytes_per_pixel
                        
                        # Estimativa grosseira de qualidade
                        if bytes_per_pixel > 3:
                            quality_metrics['estimated_quality'] = 'high'
                        elif bytes_per_pixel > 1.5:
                            quality_metrics['estimated_quality'] = 'medium'
                        else:
                            quality_metrics['estimated_quality'] = 'low'
                        
                        # Razão de compressão estimada
                        uncompressed_size = total_pixels * 3  # RGB
                        if uncompressed_size > 0:
                            quality_metrics['compression_ratio'] = file_size / uncompressed_size
            
        except Exception as e:
            logger.debug(f"Erro na análise de qualidade: {e}")
            quality_metrics['quality_analysis_error'] = str(e)
        
        return quality_metrics
