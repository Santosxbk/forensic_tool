"""
Analisador de arquivos de rede e logs para análise forense.

Este módulo fornece análise especializada para arquivos relacionados à rede,
incluindo logs de firewall, captures de pacotes, e arquivos de configuração de rede.
"""

import json
import re
import socket
import struct
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
import logging

from .base import BaseAnalyzer, AnalysisResult

logger = logging.getLogger(__name__)


class NetworkAnalyzer(BaseAnalyzer):
    """
    Analisador especializado para arquivos de rede e logs.
    
    Suporta análise de:
    - Logs de firewall (iptables, pfSense, etc.)
    - Arquivos PCAP (básico)
    - Logs de servidor web (Apache, Nginx)
    - Arquivos de configuração de rede
    - Logs de sistema relacionados à rede
    """
    
    SUPPORTED_EXTENSIONS = {
        '.log', '.pcap', '.cap', '.conf', '.cfg', 
        '.access', '.error', '.auth', '.syslog'
    }
    
    # Padrões regex para diferentes tipos de logs
    LOG_PATTERNS = {
        'apache_access': re.compile(
            r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<timestamp>[^\]]+)\] '
            r'"(?P<method>\w+) (?P<url>[^"]*)" (?P<status>\d+) (?P<size>\d+|-)'
        ),
        'nginx_access': re.compile(
            r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<timestamp>[^\]]+)\] '
            r'"(?P<method>\w+) (?P<url>[^"]*)" (?P<status>\d+) (?P<size>\d+) '
            r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
        ),
        'iptables': re.compile(
            r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+) (?P<hostname>\S+) '
            r'kernel: (?P<rule>[^:]+): IN=(?P<in_interface>\S*) OUT=(?P<out_interface>\S*) '
            r'.*SRC=(?P<src_ip>\d+\.\d+\.\d+\.\d+) DST=(?P<dst_ip>\d+\.\d+\.\d+\.\d+)'
        ),
        'ssh_auth': re.compile(
            r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+) (?P<hostname>\S+) '
            r'sshd\[\d+\]: (?P<event>Failed password|Accepted password) '
            r'for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)'
        ),
        'generic_ip': re.compile(r'\b(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
    }
    
    def can_analyze(self, file_path: Path) -> bool:
        """Verifica se o arquivo pode ser analisado por este analisador."""
        if file_path.suffix.lower() in self.SUPPORTED_EXTENSIONS:
            return True
        
        # Verificação adicional por nome de arquivo
        filename_lower = file_path.name.lower()
        network_keywords = ['access', 'error', 'auth', 'firewall', 'iptables', 'syslog']
        
        return any(keyword in filename_lower for keyword in network_keywords)
    
    def analyze(self, file_path: Path) -> AnalysisResult:
        """Executa análise completa do arquivo de rede."""
        try:
            start_time = datetime.now()
            
            # Determina o tipo de arquivo
            file_type = self._detect_file_type(file_path)
            
            # Executa análise específica baseada no tipo
            if file_type == 'pcap':
                metadata = self._analyze_pcap_file(file_path)
            elif file_type in ['apache_access', 'nginx_access']:
                metadata = self._analyze_web_log(file_path, file_type)
            elif file_type == 'iptables':
                metadata = self._analyze_firewall_log(file_path)
            elif file_type == 'ssh_auth':
                metadata = self._analyze_ssh_log(file_path)
            else:
                metadata = self._analyze_generic_log(file_path)
            
            # Adiciona informações gerais
            metadata.update({
                'file_type': file_type,
                'analysis_type': 'NetworkAnalyzer',
                'file_size': file_path.stat().st_size,
                'last_modified': datetime.fromtimestamp(file_path.stat().st_mtime).isoformat()
            })
            
            duration = (datetime.now() - start_time).total_seconds()
            
            return AnalysisResult(
                success=True,
                file_path=str(file_path),
                file_name=file_path.name,
                file_type=f"Network Log ({file_type})",
                analysis_type="NetworkAnalyzer",
                metadata=metadata,
                analysis_duration=duration
            )
            
        except Exception as e:
            logger.error(f"Erro na análise de rede do arquivo {file_path}: {e}", exc_info=True)
            return AnalysisResult(
                success=False,
                file_path=str(file_path),
                file_name=file_path.name,
                file_type="Network Log",
                analysis_type="NetworkAnalyzer",
                error_message=str(e),
                analysis_duration=0
            )
    
    def _detect_file_type(self, file_path: Path) -> str:
        """Detecta o tipo específico de arquivo de rede."""
        filename = file_path.name.lower()
        extension = file_path.suffix.lower()
        
        # Detecção por extensão
        if extension in ['.pcap', '.cap']:
            return 'pcap'
        
        # Detecção por nome do arquivo
        if 'access' in filename and ('apache' in filename or 'httpd' in filename):
            return 'apache_access'
        elif 'access' in filename and 'nginx' in filename:
            return 'nginx_access'
        elif 'iptables' in filename or 'firewall' in filename:
            return 'iptables'
        elif 'auth' in filename or 'ssh' in filename:
            return 'ssh_auth'
        
        # Detecção por conteúdo (primeiras linhas)
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                sample_lines = [f.readline().strip() for _ in range(5)]
                sample_text = '\n'.join(sample_lines)
                
                if 'apache' in sample_text.lower() or '"GET' in sample_text:
                    return 'apache_access'
                elif 'nginx' in sample_text.lower():
                    return 'nginx_access'
                elif 'iptables' in sample_text or 'kernel:' in sample_text:
                    return 'iptables'
                elif 'sshd' in sample_text:
                    return 'ssh_auth'
                    
        except Exception:
            pass
        
        return 'generic_log'
    
    def _analyze_pcap_file(self, file_path: Path) -> Dict[str, Any]:
        """Análise básica de arquivo PCAP."""
        metadata = {
            'format': 'PCAP',
            'analysis_method': 'header_inspection'
        }
        
        try:
            with open(file_path, 'rb') as f:
                # Lê o cabeçalho global do PCAP
                global_header = f.read(24)
                if len(global_header) < 24:
                    raise ValueError("Arquivo PCAP inválido")
                
                # Verifica magic number
                magic = struct.unpack('<I', global_header[:4])[0]
                if magic == 0xa1b2c3d4:
                    endian = '<'
                elif magic == 0xd4c3b2a1:
                    endian = '>'
                else:
                    raise ValueError("Magic number PCAP inválido")
                
                # Extrai informações do cabeçalho
                version_major, version_minor, _, _, snaplen, network = struct.unpack(
                    f'{endian}HHIIII', global_header[4:]
                )
                
                metadata.update({
                    'version': f"{version_major}.{version_minor}",
                    'snaplen': snaplen,
                    'network_type': network,
                    'endianness': 'little' if endian == '<' else 'big'
                })
                
                # Conta pacotes (básico)
                packet_count = 0
                while True:
                    packet_header = f.read(16)
                    if len(packet_header) < 16:
                        break
                    
                    _, _, caplen, _ = struct.unpack(f'{endian}IIII', packet_header)
                    f.seek(caplen, 1)  # Pula os dados do pacote
                    packet_count += 1
                    
                    if packet_count > 10000:  # Limite para performance
                        metadata['packet_count_note'] = 'Contagem limitada a 10000 pacotes'
                        break
                
                metadata['packet_count'] = packet_count
                
        except Exception as e:
            metadata['pcap_error'] = str(e)
        
        return metadata
    
    def _analyze_web_log(self, file_path: Path, log_type: str) -> Dict[str, Any]:
        """Análise de logs de servidor web."""
        metadata = {
            'log_type': log_type,
            'total_requests': 0,
            'unique_ips': set(),
            'status_codes': {},
            'methods': {},
            'top_urls': {},
            'suspicious_activity': []
        }
        
        pattern = self.LOG_PATTERNS[log_type]
        line_count = 0
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line_count += 1
                    if line_count > 50000:  # Limite para performance
                        metadata['analysis_note'] = 'Análise limitada às primeiras 50000 linhas'
                        break
                    
                    match = pattern.match(line.strip())
                    if match:
                        data = match.groupdict()
                        
                        metadata['total_requests'] += 1
                        metadata['unique_ips'].add(data['ip'])
                        
                        # Contagem de status codes
                        status = data.get('status', 'unknown')
                        metadata['status_codes'][status] = metadata['status_codes'].get(status, 0) + 1
                        
                        # Contagem de métodos HTTP
                        method = data.get('method', 'unknown')
                        metadata['methods'][method] = metadata['methods'].get(method, 0) + 1
                        
                        # URLs mais acessadas
                        url = data.get('url', 'unknown')
                        metadata['top_urls'][url] = metadata['top_urls'].get(url, 0) + 1
                        
                        # Detecção de atividade suspeita
                        self._detect_suspicious_web_activity(data, metadata['suspicious_activity'])
            
            # Converte sets para listas e limita resultados
            metadata['unique_ips'] = len(metadata['unique_ips'])
            metadata['top_urls'] = dict(sorted(metadata['top_urls'].items(), 
                                             key=lambda x: x[1], reverse=True)[:20])
            
        except Exception as e:
            metadata['analysis_error'] = str(e)
        
        return metadata
    
    def _analyze_firewall_log(self, file_path: Path) -> Dict[str, Any]:
        """Análise de logs de firewall."""
        metadata = {
            'log_type': 'firewall',
            'total_events': 0,
            'blocked_ips': {},
            'target_ips': {},
            'interfaces': set(),
            'rules_triggered': {},
            'attack_patterns': []
        }
        
        pattern = self.LOG_PATTERNS['iptables']
        line_count = 0
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line_count += 1
                    if line_count > 30000:  # Limite para performance
                        metadata['analysis_note'] = 'Análise limitada às primeiras 30000 linhas'
                        break
                    
                    match = pattern.search(line)
                    if match:
                        data = match.groupdict()
                        
                        metadata['total_events'] += 1
                        
                        # IPs bloqueados
                        src_ip = data.get('src_ip')
                        if src_ip:
                            metadata['blocked_ips'][src_ip] = metadata['blocked_ips'].get(src_ip, 0) + 1
                        
                        # IPs alvo
                        dst_ip = data.get('dst_ip')
                        if dst_ip:
                            metadata['target_ips'][dst_ip] = metadata['target_ips'].get(dst_ip, 0) + 1
                        
                        # Interfaces
                        in_interface = data.get('in_interface')
                        if in_interface:
                            metadata['interfaces'].add(in_interface)
                        
                        # Regras
                        rule = data.get('rule')
                        if rule:
                            metadata['rules_triggered'][rule] = metadata['rules_triggered'].get(rule, 0) + 1
                        
                        # Detecção de padrões de ataque
                        self._detect_attack_patterns(data, metadata['attack_patterns'])
            
            # Processa resultados
            metadata['interfaces'] = list(metadata['interfaces'])
            metadata['top_blocked_ips'] = dict(sorted(metadata['blocked_ips'].items(), 
                                                    key=lambda x: x[1], reverse=True)[:20])
            metadata['top_target_ips'] = dict(sorted(metadata['target_ips'].items(), 
                                                   key=lambda x: x[1], reverse=True)[:20])
            
        except Exception as e:
            metadata['analysis_error'] = str(e)
        
        return metadata
    
    def _analyze_ssh_log(self, file_path: Path) -> Dict[str, Any]:
        """Análise de logs SSH."""
        metadata = {
            'log_type': 'ssh_authentication',
            'total_attempts': 0,
            'successful_logins': 0,
            'failed_logins': 0,
            'attacking_ips': {},
            'targeted_users': {},
            'brute_force_attempts': []
        }
        
        pattern = self.LOG_PATTERNS['ssh_auth']
        line_count = 0
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line_count += 1
                    if line_count > 20000:  # Limite para performance
                        metadata['analysis_note'] = 'Análise limitada às primeiras 20000 linhas'
                        break
                    
                    match = pattern.search(line)
                    if match:
                        data = match.groupdict()
                        
                        metadata['total_attempts'] += 1
                        
                        event = data.get('event', '')
                        ip = data.get('ip', '')
                        user = data.get('user', '')
                        
                        if 'Failed' in event:
                            metadata['failed_logins'] += 1
                            if ip:
                                metadata['attacking_ips'][ip] = metadata['attacking_ips'].get(ip, 0) + 1
                        elif 'Accepted' in event:
                            metadata['successful_logins'] += 1
                        
                        if user:
                            metadata['targeted_users'][user] = metadata['targeted_users'].get(user, 0) + 1
                        
                        # Detecção de força bruta
                        self._detect_brute_force(data, metadata['brute_force_attempts'])
            
            # Processa resultados
            metadata['top_attacking_ips'] = dict(sorted(metadata['attacking_ips'].items(), 
                                                       key=lambda x: x[1], reverse=True)[:15])
            metadata['top_targeted_users'] = dict(sorted(metadata['targeted_users'].items(), 
                                                        key=lambda x: x[1], reverse=True)[:15])
            
        except Exception as e:
            metadata['analysis_error'] = str(e)
        
        return metadata
    
    def _analyze_generic_log(self, file_path: Path) -> Dict[str, Any]:
        """Análise genérica de logs de rede."""
        metadata = {
            'log_type': 'generic_network',
            'total_lines': 0,
            'ip_addresses': set(),
            'domains': set(),
            'keywords': {},
            'timestamps_found': []
        }
        
        ip_pattern = self.LOG_PATTERNS['generic_ip']
        domain_pattern = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')
        timestamp_patterns = [
            re.compile(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}'),
            re.compile(r'\w{3} \d{1,2} \d{2}:\d{2}:\d{2}'),
            re.compile(r'\[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}')
        ]
        
        network_keywords = ['error', 'warning', 'failed', 'denied', 'blocked', 'attack', 'intrusion']
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    if line_num > 10000:  # Limite para performance
                        metadata['analysis_note'] = 'Análise limitada às primeiras 10000 linhas'
                        break
                    
                    metadata['total_lines'] += 1
                    line_lower = line.lower()
                    
                    # Busca IPs
                    for ip_match in ip_pattern.finditer(line):
                        ip = ip_match.group('ip')
                        if self._is_valid_ip(ip):
                            metadata['ip_addresses'].add(ip)
                    
                    # Busca domínios
                    for domain_match in domain_pattern.finditer(line):
                        domain = domain_match.group()
                        if '.' in domain and len(domain) > 3:
                            metadata['domains'].add(domain)
                    
                    # Busca timestamps
                    for ts_pattern in timestamp_patterns:
                        ts_match = ts_pattern.search(line)
                        if ts_match and len(metadata['timestamps_found']) < 10:
                            metadata['timestamps_found'].append(ts_match.group())
                    
                    # Conta palavras-chave
                    for keyword in network_keywords:
                        if keyword in line_lower:
                            metadata['keywords'][keyword] = metadata['keywords'].get(keyword, 0) + 1
            
            # Converte sets para contagens
            metadata['unique_ips'] = len(metadata['ip_addresses'])
            metadata['unique_domains'] = len(metadata['domains'])
            metadata['sample_ips'] = list(metadata['ip_addresses'])[:20]
            metadata['sample_domains'] = list(metadata['domains'])[:20]
            
            # Remove os sets originais para serialização
            del metadata['ip_addresses']
            del metadata['domains']
            
        except Exception as e:
            metadata['analysis_error'] = str(e)
        
        return metadata
    
    def _detect_suspicious_web_activity(self, log_data: Dict[str, str], suspicious_list: List[Dict]):
        """Detecta atividade suspeita em logs web."""
        ip = log_data.get('ip', '')
        url = log_data.get('url', '')
        status = log_data.get('status', '')
        user_agent = log_data.get('user_agent', '')
        
        # Detecção de tentativas de SQL injection
        if any(keyword in url.lower() for keyword in ['union', 'select', 'drop', 'insert', "'", '"']):
            suspicious_list.append({
                'type': 'sql_injection_attempt',
                'ip': ip,
                'url': url,
                'timestamp': log_data.get('timestamp', '')
            })
        
        # Detecção de tentativas de XSS
        if any(keyword in url.lower() for keyword in ['<script', 'javascript:', 'alert(', 'onerror=']):
            suspicious_list.append({
                'type': 'xss_attempt',
                'ip': ip,
                'url': url,
                'timestamp': log_data.get('timestamp', '')
            })
        
        # User agents suspeitos
        if user_agent and any(bot in user_agent.lower() for bot in ['sqlmap', 'nikto', 'nmap', 'masscan']):
            suspicious_list.append({
                'type': 'suspicious_user_agent',
                'ip': ip,
                'user_agent': user_agent,
                'timestamp': log_data.get('timestamp', '')
            })
    
    def _detect_attack_patterns(self, log_data: Dict[str, str], attack_list: List[Dict]):
        """Detecta padrões de ataque em logs de firewall."""
        src_ip = log_data.get('src_ip', '')
        dst_ip = log_data.get('dst_ip', '')
        
        # Detecção de port scanning (simplificado)
        if src_ip and dst_ip:
            attack_list.append({
                'type': 'blocked_connection',
                'source_ip': src_ip,
                'target_ip': dst_ip,
                'timestamp': log_data.get('timestamp', '')
            })
    
    def _detect_brute_force(self, log_data: Dict[str, str], brute_force_list: List[Dict]):
        """Detecta tentativas de força bruta."""
        if 'Failed' in log_data.get('event', ''):
            brute_force_list.append({
                'ip': log_data.get('ip', ''),
                'user': log_data.get('user', ''),
                'timestamp': log_data.get('timestamp', '')
            })
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Valida se uma string é um IP válido."""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            
            for part in parts:
                num = int(part)
                if num < 0 or num > 255:
                    return False
            
            return True
        except (ValueError, AttributeError):
            return False
