"""
Analisador especializado para arquivos multimídia (áudio e vídeo)
"""

from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
import logging
from datetime import datetime, timedelta
from .base import MultiFormatAnalyzer

logger = logging.getLogger(__name__)

# Importações condicionais
try:
    import mutagen
    from mutagen.id3 import ID3NoHeaderError
    from mutagen.mp3 import MP3
    from mutagen.flac import FLAC
    from mutagen.mp4 import MP4
    from mutagen.oggvorbis import OggVorbis
    MUTAGEN_AVAILABLE = True
except ImportError:
    MUTAGEN_AVAILABLE = False

try:
    import cv2
    CV2_AVAILABLE = True
except ImportError:
    CV2_AVAILABLE = False

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False


class MediaAnalyzer(MultiFormatAnalyzer):
    """Analisador para arquivos multimídia"""
    
    def __init__(self):
        super().__init__("MediaAnalyzer")
        
        # Registrar handlers para diferentes formatos
        if MUTAGEN_AVAILABLE:
            # Áudio
            self.add_format_handler({'.mp3'}, self._analyze_mp3)
            self.add_format_handler({'.flac'}, self._analyze_flac)
            self.add_format_handler({'.m4a', '.aac'}, self._analyze_mp4_audio)
            self.add_format_handler({'.ogg'}, self._analyze_ogg)
            self.add_format_handler({'.wav', '.wma'}, self._analyze_generic_audio)
        
        if CV2_AVAILABLE:
            # Vídeo
            self.add_format_handler({
                '.mp4', '.avi', '.mkv', '.mov', '.wmv', 
                '.flv', '.webm', '.m4v', '.3gp'
            }, self._analyze_video)
        
        # Log de disponibilidade
        if not MUTAGEN_AVAILABLE:
            logger.warning("Mutagen não disponível - análise de áudio desabilitada")
        if not CV2_AVAILABLE:
            logger.warning("OpenCV não disponível - análise de vídeo desabilitada")
    
    def _analyze_mp3(self, file_path: Path) -> Dict[str, Any]:
        """Análise específica para arquivos MP3"""
        metadata = {
            'media_type': 'MP3 Audio',
            'audio_info': {},
            'id3_tags': {},
            'technical_info': {},
            'quality_analysis': {}
        }
        
        try:
            audio_file = MP3(file_path)
            
            # Informações técnicas básicas
            if audio_file.info:
                info = audio_file.info
                metadata['audio_info'] = {
                    'duration_seconds': info.length,
                    'duration_formatted': self._format_duration(info.length),
                    'bitrate': info.bitrate,
                    'sample_rate': info.sample_rate,
                    'channels': info.channels,
                    'layer': getattr(info, 'layer', 'unknown'),
                    'version': getattr(info, 'version', 'unknown'),
                    'mode': getattr(info, 'mode', 'unknown')
                }
            
            # Tags ID3
            if audio_file.tags:
                metadata['id3_tags'] = self._extract_id3_tags(audio_file.tags)
            
            # Análise técnica avançada
            metadata['technical_info'] = self._analyze_mp3_technical(audio_file)
            
            # Análise de qualidade
            metadata['quality_analysis'] = self._analyze_audio_quality(audio_file.info)
            
        except Exception as e:
            logger.error(f"Erro na análise MP3 {file_path}: {e}")
            metadata['analysis_error'] = str(e)
        
        return metadata
    
    def _analyze_flac(self, file_path: Path) -> Dict[str, Any]:
        """Análise específica para arquivos FLAC"""
        metadata = {
            'media_type': 'FLAC Audio',
            'audio_info': {},
            'vorbis_comments': {},
            'technical_info': {},
            'quality_analysis': {}
        }
        
        try:
            audio_file = FLAC(file_path)
            
            # Informações técnicas
            if audio_file.info:
                info = audio_file.info
                metadata['audio_info'] = {
                    'duration_seconds': info.length,
                    'duration_formatted': self._format_duration(info.length),
                    'bitrate': getattr(info, 'bitrate', 0),
                    'sample_rate': info.sample_rate,
                    'channels': info.channels,
                    'bits_per_sample': getattr(info, 'bits_per_sample', 'unknown'),
                    'total_samples': getattr(info, 'total_samples', 0)
                }
            
            # Comentários Vorbis
            if audio_file.tags:
                metadata['vorbis_comments'] = self._extract_vorbis_comments(audio_file.tags)
            
            # Análise técnica
            metadata['technical_info'] = self._analyze_flac_technical(audio_file)
            
            # Análise de qualidade
            metadata['quality_analysis'] = self._analyze_audio_quality(audio_file.info)
            
        except Exception as e:
            logger.error(f"Erro na análise FLAC {file_path}: {e}")
            metadata['analysis_error'] = str(e)
        
        return metadata
    
    def _analyze_mp4_audio(self, file_path: Path) -> Dict[str, Any]:
        """Análise para arquivos MP4/M4A/AAC"""
        metadata = {
            'media_type': 'MP4 Audio',
            'audio_info': {},
            'mp4_tags': {},
            'technical_info': {},
            'quality_analysis': {}
        }
        
        try:
            audio_file = MP4(file_path)
            
            # Informações técnicas
            if audio_file.info:
                info = audio_file.info
                metadata['audio_info'] = {
                    'duration_seconds': info.length,
                    'duration_formatted': self._format_duration(info.length),
                    'bitrate': info.bitrate,
                    'sample_rate': getattr(info, 'sample_rate', 0),
                    'channels': getattr(info, 'channels', 0),
                    'codec': getattr(info, 'codec', 'unknown')
                }
            
            # Tags MP4
            if audio_file.tags:
                metadata['mp4_tags'] = self._extract_mp4_tags(audio_file.tags)
            
            # Análise técnica
            metadata['technical_info'] = self._analyze_mp4_technical(audio_file)
            
            # Análise de qualidade
            metadata['quality_analysis'] = self._analyze_audio_quality(audio_file.info)
            
        except Exception as e:
            logger.error(f"Erro na análise MP4 {file_path}: {e}")
            metadata['analysis_error'] = str(e)
        
        return metadata
    
    def _analyze_ogg(self, file_path: Path) -> Dict[str, Any]:
        """Análise para arquivos OGG Vorbis"""
        metadata = {
            'media_type': 'OGG Vorbis',
            'audio_info': {},
            'vorbis_comments': {},
            'technical_info': {},
            'quality_analysis': {}
        }
        
        try:
            audio_file = OggVorbis(file_path)
            
            # Informações técnicas
            if audio_file.info:
                info = audio_file.info
                metadata['audio_info'] = {
                    'duration_seconds': info.length,
                    'duration_formatted': self._format_duration(info.length),
                    'bitrate': info.bitrate,
                    'sample_rate': getattr(info, 'sample_rate', 0),
                    'channels': info.channels,
                    'nominal_bitrate': getattr(info, 'nominal_bitrate', 0),
                    'bitrate_maximum': getattr(info, 'bitrate_maximum', 0),
                    'bitrate_minimum': getattr(info, 'bitrate_minimum', 0)
                }
            
            # Comentários Vorbis
            if audio_file.tags:
                metadata['vorbis_comments'] = self._extract_vorbis_comments(audio_file.tags)
            
            # Análise técnica
            metadata['technical_info'] = self._analyze_ogg_technical(audio_file)
            
            # Análise de qualidade
            metadata['quality_analysis'] = self._analyze_audio_quality(audio_file.info)
            
        except Exception as e:
            logger.error(f"Erro na análise OGG {file_path}: {e}")
            metadata['analysis_error'] = str(e)
        
        return metadata
    
    def _analyze_generic_audio(self, file_path: Path) -> Dict[str, Any]:
        """Análise genérica para outros formatos de áudio"""
        metadata = {
            'media_type': 'Generic Audio',
            'audio_info': {},
            'tags': {},
            'technical_info': {},
            'quality_analysis': {}
        }
        
        try:
            audio_file = mutagen.File(file_path)
            
            if audio_file:
                # Informações básicas
                if audio_file.info:
                    info = audio_file.info
                    metadata['audio_info'] = {
                        'duration_seconds': getattr(info, 'length', 0),
                        'duration_formatted': self._format_duration(getattr(info, 'length', 0)),
                        'bitrate': getattr(info, 'bitrate', 0),
                        'sample_rate': getattr(info, 'sample_rate', 0),
                        'channels': getattr(info, 'channels', 0)
                    }
                
                # Tags genéricas
                if audio_file.tags:
                    metadata['tags'] = self._extract_generic_tags(audio_file.tags)
                
                # Análise de qualidade
                metadata['quality_analysis'] = self._analyze_audio_quality(audio_file.info)
            
        except Exception as e:
            logger.error(f"Erro na análise genérica de áudio {file_path}: {e}")
            metadata['analysis_error'] = str(e)
        
        return metadata
    
    def _analyze_video(self, file_path: Path) -> Dict[str, Any]:
        """Análise para arquivos de vídeo"""
        metadata = {
            'media_type': 'Video',
            'video_info': {},
            'audio_info': {},
            'technical_info': {},
            'quality_analysis': {},
            'frame_analysis': {}
        }
        
        try:
            cap = cv2.VideoCapture(str(file_path))
            
            if not cap.isOpened():
                metadata['analysis_error'] = "Não foi possível abrir o arquivo de vídeo"
                return metadata
            
            # Informações básicas do vídeo
            metadata['video_info'] = self._extract_video_info(cap)
            
            # Análise de qualidade
            metadata['quality_analysis'] = self._analyze_video_quality(cap)
            
            # Análise de frames (limitada)
            metadata['frame_analysis'] = self._analyze_video_frames(cap, max_frames=10)
            
            # Informações técnicas adicionais
            metadata['technical_info'] = self._analyze_video_technical(cap)
            
            cap.release()
            
        except Exception as e:
            logger.error(f"Erro na análise de vídeo {file_path}: {e}")
            metadata['analysis_error'] = str(e)
        
        return metadata
    
    def _extract_video_info(self, cap) -> Dict[str, Any]:
        """Extrai informações básicas do vídeo"""
        try:
            fps = cap.get(cv2.CAP_PROP_FPS)
            frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
            height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
            
            duration = frame_count / fps if fps > 0 else 0
            
            return {
                'width': width,
                'height': height,
                'resolution': f"{width}x{height}",
                'fps': round(fps, 2),
                'frame_count': frame_count,
                'duration_seconds': round(duration, 2),
                'duration_formatted': self._format_duration(duration),
                'aspect_ratio': round(width / height, 2) if height > 0 else 0,
                'codec': self._get_video_codec(cap)
            }
            
        except Exception as e:
            logger.debug(f"Erro ao extrair informações de vídeo: {e}")
            return {'extraction_error': str(e)}
    
    def _analyze_video_quality(self, cap) -> Dict[str, Any]:
        """Análise de qualidade do vídeo"""
        quality_info = {
            'resolution_category': 'unknown',
            'fps_category': 'unknown',
            'estimated_bitrate': 0,
            'quality_score': 0
        }
        
        try:
            width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
            height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
            fps = cap.get(cv2.CAP_PROP_FPS)
            
            # Categorizar resolução
            total_pixels = width * height
            if total_pixels >= 3840 * 2160:  # 4K
                quality_info['resolution_category'] = '4K'
                quality_score = 10
            elif total_pixels >= 1920 * 1080:  # Full HD
                quality_info['resolution_category'] = 'Full HD'
                quality_score = 8
            elif total_pixels >= 1280 * 720:  # HD
                quality_info['resolution_category'] = 'HD'
                quality_score = 6
            elif total_pixels >= 854 * 480:  # SD
                quality_info['resolution_category'] = 'SD'
                quality_score = 4
            else:
                quality_info['resolution_category'] = 'Low'
                quality_score = 2
            
            # Categorizar FPS
            if fps >= 60:
                quality_info['fps_category'] = 'High (60+ fps)'
                quality_score += 2
            elif fps >= 30:
                quality_info['fps_category'] = 'Standard (30+ fps)'
                quality_score += 1
            elif fps >= 24:
                quality_info['fps_category'] = 'Cinema (24+ fps)'
            else:
                quality_info['fps_category'] = 'Low (<24 fps)'
                quality_score -= 1
            
            quality_info['quality_score'] = max(0, min(10, quality_score))
            
        except Exception as e:
            logger.debug(f"Erro na análise de qualidade de vídeo: {e}")
            quality_info['quality_analysis_error'] = str(e)
        
        return quality_info
    
    def _analyze_video_frames(self, cap, max_frames: int = 10) -> Dict[str, Any]:
        """Análise de frames do vídeo"""
        if not NUMPY_AVAILABLE:
            return {'frame_analysis_error': 'NumPy não disponível'}
        
        frame_analysis = {
            'frames_analyzed': 0,
            'average_brightness': 0,
            'brightness_variance': 0,
            'motion_detected': False,
            'scene_changes': 0
        }
        
        try:
            frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            if frame_count == 0:
                return frame_analysis
            
            # Selecionar frames para análise
            frame_indices = np.linspace(0, frame_count - 1, min(max_frames, frame_count), dtype=int)
            
            brightness_values = []
            previous_frame = None
            scene_changes = 0
            
            for frame_idx in frame_indices:
                cap.set(cv2.CAP_PROP_POS_FRAMES, frame_idx)
                ret, frame = cap.read()
                
                if not ret:
                    continue
                
                # Converter para escala de cinza
                gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                
                # Calcular brilho médio
                brightness = np.mean(gray)
                brightness_values.append(brightness)
                
                # Detectar mudanças de cena (simplificado)
                if previous_frame is not None:
                    diff = cv2.absdiff(previous_frame, gray)
                    change_percentage = (np.count_nonzero(diff > 30) / diff.size) * 100
                    
                    if change_percentage > 20:  # Threshold arbitrário
                        scene_changes += 1
                
                previous_frame = gray.copy()
                frame_analysis['frames_analyzed'] += 1
            
            # Calcular estatísticas
            if brightness_values:
                frame_analysis['average_brightness'] = float(np.mean(brightness_values))
                frame_analysis['brightness_variance'] = float(np.var(brightness_values))
                frame_analysis['scene_changes'] = scene_changes
                frame_analysis['motion_detected'] = scene_changes > 0
            
        except Exception as e:
            logger.debug(f"Erro na análise de frames: {e}")
            frame_analysis['frame_analysis_error'] = str(e)
        
        return frame_analysis
    
    def _analyze_video_technical(self, cap) -> Dict[str, Any]:
        """Análise técnica adicional do vídeo"""
        technical_info = {
            'backend': 'unknown',
            'fourcc': 'unknown',
            'buffer_size': 0,
            'pos_msec': 0
        }
        
        try:
            # Informações técnicas do OpenCV
            technical_info['backend'] = cap.getBackendName()
            
            # FourCC (codec)
            fourcc = cap.get(cv2.CAP_PROP_FOURCC)
            if fourcc:
                fourcc_str = "".join([chr((int(fourcc) >> 8 * i) & 0xFF) for i in range(4)])
                technical_info['fourcc'] = fourcc_str
            
            # Outras propriedades
            technical_info['buffer_size'] = int(cap.get(cv2.CAP_PROP_BUFFERSIZE))
            technical_info['pos_msec'] = cap.get(cv2.CAP_PROP_POS_MSEC)
            
        except Exception as e:
            logger.debug(f"Erro na análise técnica de vídeo: {e}")
            technical_info['technical_analysis_error'] = str(e)
        
        return technical_info
    
    def _get_video_codec(self, cap) -> str:
        """Obtém codec do vídeo"""
        try:
            fourcc = cap.get(cv2.CAP_PROP_FOURCC)
            if fourcc:
                return "".join([chr((int(fourcc) >> 8 * i) & 0xFF) for i in range(4)])
            return 'unknown'
        except:
            return 'unknown'
    
    def _extract_id3_tags(self, tags) -> Dict[str, Any]:
        """Extrai tags ID3 de arquivos MP3"""
        id3_tags = {}
        
        try:
            # Mapeamento de tags comuns
            tag_mapping = {
                'TIT2': 'title',
                'TPE1': 'artist',
                'TALB': 'album',
                'TDRC': 'year',
                'TCON': 'genre',
                'TPE2': 'album_artist',
                'TRCK': 'track_number',
                'TPOS': 'disc_number',
                'COMM::eng': 'comment'
            }
            
            for tag_id, value in tags.items():
                tag_name = tag_mapping.get(str(tag_id), str(tag_id))
                
                # Processar valor
                if hasattr(value, 'text'):
                    processed_value = str(value.text[0]) if value.text else ''
                else:
                    processed_value = str(value)
                
                id3_tags[tag_name] = processed_value
                
        except Exception as e:
            logger.debug(f"Erro ao extrair tags ID3: {e}")
            id3_tags['tag_extraction_error'] = str(e)
        
        return id3_tags
    
    def _extract_vorbis_comments(self, tags) -> Dict[str, Any]:
        """Extrai comentários Vorbis"""
        vorbis_tags = {}
        
        try:
            for key, value in tags.items():
                if isinstance(value, list):
                    vorbis_tags[key.lower()] = value[0] if value else ''
                else:
                    vorbis_tags[key.lower()] = str(value)
                    
        except Exception as e:
            logger.debug(f"Erro ao extrair comentários Vorbis: {e}")
            vorbis_tags['vorbis_extraction_error'] = str(e)
        
        return vorbis_tags
    
    def _extract_mp4_tags(self, tags) -> Dict[str, Any]:
        """Extrai tags MP4"""
        mp4_tags = {}
        
        try:
            # Mapeamento de atoms MP4
            atom_mapping = {
                '©nam': 'title',
                '©ART': 'artist',
                '©alb': 'album',
                '©day': 'year',
                '©gen': 'genre',
                'trkn': 'track_number',
                'disk': 'disc_number',
                '©cmt': 'comment'
            }
            
            for atom, value in tags.items():
                tag_name = atom_mapping.get(atom, atom)
                
                if isinstance(value, list):
                    processed_value = str(value[0]) if value else ''
                else:
                    processed_value = str(value)
                
                mp4_tags[tag_name] = processed_value
                
        except Exception as e:
            logger.debug(f"Erro ao extrair tags MP4: {e}")
            mp4_tags['mp4_extraction_error'] = str(e)
        
        return mp4_tags
    
    def _extract_generic_tags(self, tags) -> Dict[str, Any]:
        """Extrai tags genéricas"""
        generic_tags = {}
        
        try:
            for key, value in tags.items():
                if isinstance(value, list):
                    generic_tags[str(key)] = str(value[0]) if value else ''
                else:
                    generic_tags[str(key)] = str(value)
                    
        except Exception as e:
            logger.debug(f"Erro ao extrair tags genéricas: {e}")
            generic_tags['generic_extraction_error'] = str(e)
        
        return generic_tags
    
    def _analyze_mp3_technical(self, audio_file) -> Dict[str, Any]:
        """Análise técnica específica para MP3"""
        technical_info = {}
        
        try:
            if hasattr(audio_file, 'info'):
                info = audio_file.info
                technical_info.update({
                    'mpeg_version': getattr(info, 'version', 'unknown'),
                    'layer': getattr(info, 'layer', 'unknown'),
                    'mode': getattr(info, 'mode', 'unknown'),
                    'protected': getattr(info, 'protected', False),
                    'padding': getattr(info, 'padding', False),
                    'private': getattr(info, 'private', False),
                    'copyright': getattr(info, 'copyright', False),
                    'original': getattr(info, 'original', False)
                })
                
        except Exception as e:
            logger.debug(f"Erro na análise técnica MP3: {e}")
            technical_info['mp3_technical_error'] = str(e)
        
        return technical_info
    
    def _analyze_flac_technical(self, audio_file) -> Dict[str, Any]:
        """Análise técnica específica para FLAC"""
        technical_info = {}
        
        try:
            if hasattr(audio_file, 'info'):
                info = audio_file.info
                technical_info.update({
                    'bits_per_sample': getattr(info, 'bits_per_sample', 'unknown'),
                    'total_samples': getattr(info, 'total_samples', 0),
                    'md5_signature': getattr(info, 'md5_signature', 'unknown')
                })
                
        except Exception as e:
            logger.debug(f"Erro na análise técnica FLAC: {e}")
            technical_info['flac_technical_error'] = str(e)
        
        return technical_info
    
    def _analyze_mp4_technical(self, audio_file) -> Dict[str, Any]:
        """Análise técnica específica para MP4"""
        technical_info = {}
        
        try:
            if hasattr(audio_file, 'info'):
                info = audio_file.info
                technical_info.update({
                    'codec': getattr(info, 'codec', 'unknown'),
                    'codec_description': getattr(info, 'codec_description', 'unknown')
                })
                
        except Exception as e:
            logger.debug(f"Erro na análise técnica MP4: {e}")
            technical_info['mp4_technical_error'] = str(e)
        
        return technical_info
    
    def _analyze_ogg_technical(self, audio_file) -> Dict[str, Any]:
        """Análise técnica específica para OGG"""
        technical_info = {}
        
        try:
            if hasattr(audio_file, 'info'):
                info = audio_file.info
                technical_info.update({
                    'nominal_bitrate': getattr(info, 'nominal_bitrate', 0),
                    'bitrate_maximum': getattr(info, 'bitrate_maximum', 0),
                    'bitrate_minimum': getattr(info, 'bitrate_minimum', 0),
                    'serial': getattr(info, 'serial', 0)
                })
                
        except Exception as e:
            logger.debug(f"Erro na análise técnica OGG: {e}")
            technical_info['ogg_technical_error'] = str(e)
        
        return technical_info
    
    def _analyze_audio_quality(self, info) -> Dict[str, Any]:
        """Análise de qualidade de áudio"""
        quality_analysis = {
            'quality_category': 'unknown',
            'bitrate_category': 'unknown',
            'sample_rate_category': 'unknown',
            'quality_score': 0
        }
        
        try:
            bitrate = getattr(info, 'bitrate', 0)
            sample_rate = getattr(info, 'sample_rate', 0)
            
            quality_score = 0
            
            # Categorizar bitrate
            if bitrate >= 320:
                quality_analysis['bitrate_category'] = 'Very High (320+ kbps)'
                quality_score += 4
            elif bitrate >= 256:
                quality_analysis['bitrate_category'] = 'High (256+ kbps)'
                quality_score += 3
            elif bitrate >= 192:
                quality_analysis['bitrate_category'] = 'Good (192+ kbps)'
                quality_score += 2
            elif bitrate >= 128:
                quality_analysis['bitrate_category'] = 'Standard (128+ kbps)'
                quality_score += 1
            else:
                quality_analysis['bitrate_category'] = 'Low (<128 kbps)'
            
            # Categorizar sample rate
            if sample_rate >= 96000:
                quality_analysis['sample_rate_category'] = 'Very High (96+ kHz)'
                quality_score += 2
            elif sample_rate >= 48000:
                quality_analysis['sample_rate_category'] = 'High (48+ kHz)'
                quality_score += 1
            elif sample_rate >= 44100:
                quality_analysis['sample_rate_category'] = 'CD Quality (44.1 kHz)'
                quality_score += 1
            else:
                quality_analysis['sample_rate_category'] = 'Low (<44.1 kHz)'
            
            # Categoria geral de qualidade
            if quality_score >= 5:
                quality_analysis['quality_category'] = 'Excellent'
            elif quality_score >= 3:
                quality_analysis['quality_category'] = 'Good'
            elif quality_score >= 1:
                quality_analysis['quality_category'] = 'Fair'
            else:
                quality_analysis['quality_category'] = 'Poor'
            
            quality_analysis['quality_score'] = quality_score
            
        except Exception as e:
            logger.debug(f"Erro na análise de qualidade de áudio: {e}")
            quality_analysis['quality_analysis_error'] = str(e)
        
        return quality_analysis
    
    def _format_duration(self, seconds: float) -> str:
        """Formata duração em segundos para formato legível"""
        try:
            if seconds <= 0:
                return "00:00"
            
            td = timedelta(seconds=seconds)
            total_seconds = int(td.total_seconds())
            hours, remainder = divmod(total_seconds, 3600)
            minutes, seconds = divmod(remainder, 60)
            
            if hours > 0:
                return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
            else:
                return f"{minutes:02d}:{seconds:02d}"
                
        except Exception:
            return "00:00"
