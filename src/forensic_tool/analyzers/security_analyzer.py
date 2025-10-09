"""
Analisador de segurança para detecção de malware e análise de arquivos suspeitos.

Este módulo fornece análise de segurança avançada, incluindo detecção de padrões
maliciosos, análise de entropy, verificação de assinaturas e detecção de packers.
"""

import hashlib
import math
import re
import struct
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Set
from datetime import datetime
import logging

from .base import BaseAnalyzer, AnalysisResult

logger = logging.getLogger(__name__)


class SecurityAnalyzer(BaseAnalyzer):
    """
    Analisador especializado em segurança e detecção de malware.
    
    Funcionalidades:
    - Análise de entropy para detecção de packers/criptografia
    - Detecção de strings suspeitas
    - Análise de cabeçalhos PE (Windows executables)
    - Verificação de assinaturas conhecidas de malware
    - Detecção de padrões de ofuscação
    - Análise de URLs e domínios suspeitos
    """
    
    SUPPORTED_EXTENSIONS = {
        '.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js',
        '.jar', '.apk', '.dex', '.so', '.dylib', '.bin', '.com', '.pif'
    }
    
    # Assinaturas conhecidas de malware (simplificadas para demonstração)
    MALWARE_SIGNATURES = {
        b'EICAR-STANDARD-ANTIVIRUS-TEST-FILE': 'EICAR Test File',
        b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR': 'EICAR Variant',
        b'TVqQAAMAAAAEAAAA': 'PE Header (Base64)',
        b'UEsDBBQAAAAI': 'ZIP with suspicious compression',
    }
    
    # Strings suspeitas comuns em malware
    SUSPICIOUS_STRINGS = {
        'network': [
            'CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory',
            'SetWindowsHookEx', 'GetProcAddress', 'LoadLibrary',
            'URLDownloadToFile', 'InternetOpen', 'HttpSendRequest'
        ],
        'persistence': [
            'RegSetValueEx', 'RegCreateKeyEx', 'CreateService',
            'SetFileAttributes', 'MoveFile', 'CopyFile'
        ],
        'evasion': [
            'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
            'GetTickCount', 'Sleep', 'VirtualProtect'
        ],
        'crypto': [
            'CryptAcquireContext', 'CryptCreateHash', 'CryptEncrypt',
            'CryptDecrypt', 'CryptGenKey'
        ]
    }
    
    # Domínios e URLs suspeitas (patterns)
    SUSPICIOUS_URL_PATTERNS = [
        r'bit\.ly', r'tinyurl\.com', r'goo\.gl',  # URL shorteners
        r'\d+\.\d+\.\d+\.\d+',  # IP addresses instead of domains
        r'[a-z]{10,}\.tk', r'[a-z]{10,}\.ml',  # Suspicious TLDs with random names
        r'temp-?mail', r'guerrilla-?mail',  # Temporary email services
    ]
    
    def can_analyze(self, file_path: Path) -> bool:
        """Verifica se o arquivo pode ser analisado por este analisador."""
        extension = file_path.suffix.lower()
        
        # Verifica extensões suspeitas
        if extension in self.SUPPORTED_EXTENSIONS:
            return True
        
        # Verifica arquivos sem extensão que podem ser executáveis
        if not extension and file_path.is_file():
            try:
                with open(file_path, 'rb') as f:
                    header = f.read(4)
                    # Verifica magic numbers de executáveis
                    if header.startswith(b'MZ') or header.startswith(b'\x7fELF'):
                        return True
            except Exception:
                pass
        
        return False
    
    def analyze(self, file_path: Path) -> AnalysisResult:
        """Executa análise completa de segurança do arquivo."""
        try:
            start_time = datetime.now()
            
            metadata = {
                'security_analysis': True,
                'file_size': file_path.stat().st_size,
                'last_modified': datetime.fromtimestamp(file_path.stat().st_mtime).isoformat()
            }
            
            # Análise de entropy
            entropy_data = self._calculate_entropy(file_path)
            metadata['entropy_analysis'] = entropy_data
            
            # Detecção de assinaturas
            signature_data = self._check_malware_signatures(file_path)
            metadata['signature_analysis'] = signature_data
            
            # Análise de strings suspeitas
            strings_data = self._analyze_suspicious_strings(file_path)
            metadata['strings_analysis'] = strings_data
            
            # Análise de cabeçalho PE (se aplicável)
            if file_path.suffix.lower() in ['.exe', '.dll', '.scr']:
                pe_data = self._analyze_pe_header(file_path)
                metadata['pe_analysis'] = pe_data
            
            # Análise de URLs e domínios
            url_data = self._analyze_urls_and_domains(file_path)
            metadata['url_analysis'] = url_data
            
            # Cálculo de score de risco
            risk_score = self._calculate_risk_score(metadata)
            metadata['risk_assessment'] = risk_score
            
            duration = (datetime.now() - start_time).total_seconds()
            
            return AnalysisResult(
                success=True,
                file_path=str(file_path),
                file_name=file_path.name,
                file_type=f"Security Analysis ({file_path.suffix or 'unknown'})",
                analysis_type="SecurityAnalyzer",
                metadata=metadata,
                analysis_duration=duration
            )
            
        except Exception as e:
            logger.error(f"Erro na análise de segurança do arquivo {file_path}: {e}", exc_info=True)
            return AnalysisResult(
                success=False,
                file_path=str(file_path),
                file_name=file_path.name,
                file_type="Security Analysis",
                analysis_type="SecurityAnalyzer",
                error_message=str(e),
                analysis_duration=0
            )
    
    def _calculate_entropy(self, file_path: Path) -> Dict[str, Any]:
        """Calcula a entropy do arquivo para detectar compressão/criptografia."""
        try:
            with open(file_path, 'rb') as f:
                data = f.read(1024 * 1024)  # Lê até 1MB para análise
            
            if not data:
                return {'entropy': 0, 'analysis': 'empty_file'}
            
            # Conta frequência de bytes
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
            
            # Calcula entropy
            entropy = 0
            data_len = len(data)
            
            for count in byte_counts:
                if count > 0:
                    probability = count / data_len
                    entropy -= probability * math.log2(probability)
            
            # Análise da entropy
            analysis = self._interpret_entropy(entropy)
            
            # Análise por seções (primeiros/últimos bytes)
            section_analysis = self._analyze_entropy_sections(data)
            
            return {
                'entropy': round(entropy, 4),
                'max_entropy': 8.0,
                'analysis': analysis,
                'sections': section_analysis,
                'bytes_analyzed': len(data)
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _interpret_entropy(self, entropy: float) -> Dict[str, Any]:
        """Interpreta o valor de entropy."""
        if entropy < 1.0:
            level = 'very_low'
            description = 'Arquivo muito estruturado ou com muitos zeros'
        elif entropy < 3.0:
            level = 'low'
            description = 'Arquivo estruturado, provavelmente texto ou dados simples'
        elif entropy < 6.0:
            level = 'medium'
            description = 'Arquivo normal, mistura de dados estruturados'
        elif entropy < 7.5:
            level = 'high'
            description = 'Arquivo comprimido ou com dados diversos'
        else:
            level = 'very_high'
            description = 'Possível arquivo criptografado, comprimido ou packed'
        
        return {
            'level': level,
            'description': description,
            'suspicious': entropy > 7.0
        }
    
    def _analyze_entropy_sections(self, data: bytes) -> Dict[str, float]:
        """Analisa entropy em diferentes seções do arquivo."""
        sections = {}
        data_len = len(data)
        
        if data_len >= 1024:
            # Início do arquivo
            start_section = data[:512]
            sections['start'] = self._calculate_section_entropy(start_section)
            
            # Meio do arquivo
            mid_start = data_len // 2 - 256
            mid_section = data[mid_start:mid_start + 512]
            sections['middle'] = self._calculate_section_entropy(mid_section)
            
            # Final do arquivo
            end_section = data[-512:]
            sections['end'] = self._calculate_section_entropy(end_section)
        
        return sections
    
    def _calculate_section_entropy(self, data: bytes) -> float:
        """Calcula entropy de uma seção específica."""
        if not data:
            return 0
        
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        entropy = 0
        data_len = len(data)
        
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)
        
        return round(entropy, 4)
    
    def _check_malware_signatures(self, file_path: Path) -> Dict[str, Any]:
        """Verifica assinaturas conhecidas de malware."""
        signatures_found = []
        
        try:
            with open(file_path, 'rb') as f:
                # Lê o arquivo em chunks para arquivos grandes
                chunk_size = 1024 * 1024  # 1MB
                data = f.read(chunk_size)
                
                for signature, description in self.MALWARE_SIGNATURES.items():
                    if signature in data:
                        signatures_found.append({
                            'signature': signature.hex(),
                            'description': description,
                            'location': 'file_content'
                        })
            
            return {
                'signatures_found': signatures_found,
                'total_signatures_checked': len(self.MALWARE_SIGNATURES),
                'is_suspicious': len(signatures_found) > 0
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_suspicious_strings(self, file_path: Path) -> Dict[str, Any]:
        """Analisa strings suspeitas no arquivo."""
        suspicious_found = {category: [] for category in self.SUSPICIOUS_STRINGS.keys()}
        total_found = 0
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read(1024 * 1024)  # Lê até 1MB
                
                # Converte para string ignorando erros
                try:
                    text_data = data.decode('utf-8', errors='ignore')
                except:
                    text_data = data.decode('latin-1', errors='ignore')
                
                text_lower = text_data.lower()
                
                for category, strings in self.SUSPICIOUS_STRINGS.items():
                    for suspicious_string in strings:
                        if suspicious_string.lower() in text_lower:
                            suspicious_found[category].append(suspicious_string)
                            total_found += 1
            
            return {
                'categories': suspicious_found,
                'total_suspicious_strings': total_found,
                'is_suspicious': total_found > 0,
                'risk_level': self._assess_string_risk(total_found)
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _assess_string_risk(self, count: int) -> str:
        """Avalia o nível de risco baseado na quantidade de strings suspeitas."""
        if count == 0:
            return 'low'
        elif count <= 3:
            return 'medium'
        elif count <= 7:
            return 'high'
        else:
            return 'critical'
    
    def _analyze_pe_header(self, file_path: Path) -> Dict[str, Any]:
        """Analisa cabeçalho PE de executáveis Windows."""
        try:
            with open(file_path, 'rb') as f:
                # Verifica assinatura DOS
                dos_header = f.read(64)
                if len(dos_header) < 64 or not dos_header.startswith(b'MZ'):
                    return {'error': 'Invalid DOS header'}
                
                # Obtém offset do cabeçalho PE
                pe_offset = struct.unpack('<I', dos_header[60:64])[0]
                
                # Lê cabeçalho PE
                f.seek(pe_offset)
                pe_signature = f.read(4)
                
                if pe_signature != b'PE\x00\x00':
                    return {'error': 'Invalid PE signature'}
                
                # Lê COFF header
                coff_header = f.read(20)
                machine, num_sections, timestamp, _, _, opt_header_size, characteristics = struct.unpack('<HHIIIHH', coff_header)
                
                # Lê cabeçalho opcional
                opt_header = f.read(min(opt_header_size, 224))
                
                analysis = {
                    'valid_pe': True,
                    'machine_type': self._get_machine_type(machine),
                    'number_of_sections': num_sections,
                    'timestamp': datetime.fromtimestamp(timestamp).isoformat() if timestamp > 0 else 'invalid',
                    'characteristics': self._parse_characteristics(characteristics),
                    'optional_header_size': opt_header_size
                }
                
                # Análise de suspeição baseada em características
                analysis['suspicious_indicators'] = self._check_pe_suspicious_indicators(analysis)
                
                return analysis
                
        except Exception as e:
            return {'error': str(e)}
    
    def _get_machine_type(self, machine: int) -> str:
        """Converte código de máquina para string legível."""
        machine_types = {
            0x014c: 'i386',
            0x0200: 'ia64',
            0x8664: 'x64',
            0x01c0: 'arm',
            0xaa64: 'arm64'
        }
        return machine_types.get(machine, f'unknown_0x{machine:04x}')
    
    def _parse_characteristics(self, characteristics: int) -> List[str]:
        """Converte características do PE para lista legível."""
        flags = []
        characteristic_flags = {
            0x0001: 'RELOCS_STRIPPED',
            0x0002: 'EXECUTABLE_IMAGE',
            0x0004: 'LINE_NUMBERS_STRIPPED',
            0x0008: 'LOCAL_SYMS_STRIPPED',
            0x0010: 'AGGR_WS_TRIM',
            0x0020: 'LARGE_ADDRESS_AWARE',
            0x0080: 'BYTES_REVERSED_LO',
            0x0100: '32BIT_MACHINE',
            0x0200: 'DEBUG_STRIPPED',
            0x0400: 'REMOVABLE_RUN_FROM_SWAP',
            0x0800: 'NET_RUN_FROM_SWAP',
            0x1000: 'SYSTEM',
            0x2000: 'DLL',
            0x4000: 'UP_SYSTEM_ONLY',
            0x8000: 'BYTES_REVERSED_HI'
        }
        
        for flag, name in characteristic_flags.items():
            if characteristics & flag:
                flags.append(name)
        
        return flags
    
    def _check_pe_suspicious_indicators(self, pe_analysis: Dict[str, Any]) -> List[str]:
        """Verifica indicadores suspeitos no PE."""
        indicators = []
        
        # Timestamp muito antigo ou futuro
        timestamp_str = pe_analysis.get('timestamp', '')
        if timestamp_str != 'invalid':
            try:
                timestamp = datetime.fromisoformat(timestamp_str)
                now = datetime.now()
                if timestamp.year < 1990 or timestamp > now:
                    indicators.append('suspicious_timestamp')
            except:
                pass
        
        # Muitas seções (possível packer)
        num_sections = pe_analysis.get('number_of_sections', 0)
        if num_sections > 10:
            indicators.append('excessive_sections')
        elif num_sections < 2:
            indicators.append('too_few_sections')
        
        # Características suspeitas
        characteristics = pe_analysis.get('characteristics', [])
        if 'SYSTEM' in characteristics:
            indicators.append('system_file_flag')
        
        return indicators
    
    def _analyze_urls_and_domains(self, file_path: Path) -> Dict[str, Any]:
        """Analisa URLs e domínios suspeitos no arquivo."""
        urls_found = []
        domains_found = []
        suspicious_patterns = []
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read(1024 * 1024)  # Lê até 1MB
                
                try:
                    text_data = data.decode('utf-8', errors='ignore')
                except:
                    text_data = data.decode('latin-1', errors='ignore')
                
                # Busca URLs
                url_pattern = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)
                urls = url_pattern.findall(text_data)
                urls_found.extend(urls[:20])  # Limita a 20 URLs
                
                # Busca domínios
                domain_pattern = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')
                domains = domain_pattern.findall(text_data)
                domains_found.extend(list(set(domains))[:30])  # Limita a 30 domínios únicos
                
                # Verifica padrões suspeitos
                for pattern in self.SUSPICIOUS_URL_PATTERNS:
                    matches = re.findall(pattern, text_data, re.IGNORECASE)
                    if matches:
                        suspicious_patterns.append({
                            'pattern': pattern,
                            'matches': matches[:10]  # Limita a 10 matches por padrão
                        })
            
            return {
                'urls_found': urls_found,
                'domains_found': domains_found,
                'suspicious_patterns': suspicious_patterns,
                'total_urls': len(urls_found),
                'total_domains': len(domains_found),
                'has_suspicious_urls': len(suspicious_patterns) > 0
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _calculate_risk_score(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Calcula score de risco baseado em todas as análises."""
        risk_score = 0
        risk_factors = []
        
        # Entropy analysis
        entropy_data = metadata.get('entropy_analysis', {})
        if entropy_data.get('analysis', {}).get('suspicious', False):
            risk_score += 30
            risk_factors.append('High entropy (possible encryption/packing)')
        
        # Signature analysis
        signature_data = metadata.get('signature_analysis', {})
        if signature_data.get('is_suspicious', False):
            risk_score += 50
            risk_factors.append('Known malware signatures detected')
        
        # Strings analysis
        strings_data = metadata.get('strings_analysis', {})
        string_risk = strings_data.get('risk_level', 'low')
        if string_risk == 'critical':
            risk_score += 40
            risk_factors.append('Critical suspicious strings found')
        elif string_risk == 'high':
            risk_score += 25
            risk_factors.append('High number of suspicious strings')
        elif string_risk == 'medium':
            risk_score += 10
            risk_factors.append('Some suspicious strings found')
        
        # PE analysis
        pe_data = metadata.get('pe_analysis', {})
        pe_indicators = pe_data.get('suspicious_indicators', [])
        if pe_indicators:
            risk_score += len(pe_indicators) * 5
            risk_factors.append(f'PE suspicious indicators: {", ".join(pe_indicators)}')
        
        # URL analysis
        url_data = metadata.get('url_analysis', {})
        if url_data.get('has_suspicious_urls', False):
            risk_score += 15
            risk_factors.append('Suspicious URLs or domains found')
        
        # Determina nível de risco
        if risk_score >= 80:
            risk_level = 'critical'
        elif risk_score >= 50:
            risk_level = 'high'
        elif risk_score >= 25:
            risk_level = 'medium'
        elif risk_score > 0:
            risk_level = 'low'
        else:
            risk_level = 'minimal'
        
        return {
            'risk_score': min(risk_score, 100),  # Máximo 100
            'risk_level': risk_level,
            'risk_factors': risk_factors,
            'recommendation': self._get_risk_recommendation(risk_level)
        }
    
    def _get_risk_recommendation(self, risk_level: str) -> str:
        """Retorna recomendação baseada no nível de risco."""
        recommendations = {
            'minimal': 'File appears safe for normal use',
            'low': 'Exercise normal caution, monitor for unusual behavior',
            'medium': 'Increased caution recommended, scan with updated antivirus',
            'high': 'High risk detected, avoid execution, submit for analysis',
            'critical': 'Critical risk - DO NOT EXECUTE, isolate immediately'
        }
        return recommendations.get(risk_level, 'Unknown risk level')
