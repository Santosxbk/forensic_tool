"""
Gerador de relatórios para análises forenses
"""

import json
import csv
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

# Importações condicionais
try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False

try:
    from jinja2 import Template
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False


class ReportGenerator:
    """Gerador de relatórios em múltiplos formatos"""
    
    def __init__(self, analysis_manager):
        """
        Inicializa o gerador de relatórios
        
        Args:
            analysis_manager: Instância do AnalysisManager
        """
        self.analysis_manager = analysis_manager
    
    def generate_reports(self, 
                        session_id: str, 
                        output_dir: Path, 
                        formats: List[str]) -> List[Path]:
        """
        Gera relatórios em múltiplos formatos
        
        Args:
            session_id: ID da sessão de análise
            output_dir: Diretório de saída
            formats: Lista de formatos (json, csv, excel, html)
            
        Returns:
            Lista de arquivos gerados
        """
        generated_files = []
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        try:
            # Obter dados da análise
            session = self.analysis_manager.get_analysis_session(session_id)
            results = self.analysis_manager.get_analysis_results(session_id, limit=100000)
            statistics = self.analysis_manager.get_session_statistics(session_id)
            
            if not session or not results:
                logger.warning(f"Nenhum dado encontrado para sessão {session_id}")
                return generated_files
            
            # Gerar cada formato solicitado
            for format_type in formats:
                format_type = format_type.lower().strip()
                
                try:
                    if format_type == 'json':
                        file_path = self._generate_json_report(
                            session, results, statistics, output_dir, timestamp
                        )
                        if file_path:
                            generated_files.append(file_path)
                    
                    elif format_type == 'csv':
                        file_path = self._generate_csv_report(
                            session, results, statistics, output_dir, timestamp
                        )
                        if file_path:
                            generated_files.append(file_path)
                    
                    elif format_type == 'excel' and PANDAS_AVAILABLE:
                        file_path = self._generate_excel_report(
                            session, results, statistics, output_dir, timestamp
                        )
                        if file_path:
                            generated_files.append(file_path)
                    
                    elif format_type == 'html' and JINJA2_AVAILABLE:
                        file_path = self._generate_html_report(
                            session, results, statistics, output_dir, timestamp
                        )
                        if file_path:
                            generated_files.append(file_path)
                    
                    else:
                        logger.warning(f"Formato não suportado ou dependência ausente: {format_type}")
                
                except Exception as e:
                    logger.error(f"Erro ao gerar relatório {format_type}: {e}")
            
            return generated_files
            
        except Exception as e:
            logger.error(f"Erro na geração de relatórios: {e}")
            return generated_files
    
    def _generate_json_report(self, 
                             session, 
                             results: List[Dict[str, Any]], 
                             statistics: Dict[str, Any],
                             output_dir: Path, 
                             timestamp: str) -> Optional[Path]:
        """Gera relatório em formato JSON"""
        try:
            file_path = output_dir / f"forensic_analysis_{timestamp}.json"
            
            report_data = {
                'metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'forensic_tool_version': '2.0.0',
                    'session_id': session.session_id,
                    'report_type': 'forensic_analysis'
                },
                'session_info': session.to_dict(),
                'statistics': statistics,
                'results': results
            }
            
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False, default=str)
            
            logger.info(f"Relatório JSON gerado: {file_path}")
            return file_path
            
        except Exception as e:
            logger.error(f"Erro ao gerar relatório JSON: {e}")
            return None
    
    def _generate_csv_report(self, 
                            session, 
                            results: List[Dict[str, Any]], 
                            statistics: Dict[str, Any],
                            output_dir: Path, 
                            timestamp: str) -> Optional[Path]:
        """Gera relatório em formato CSV"""
        try:
            file_path = output_dir / f"forensic_analysis_{timestamp}.csv"
            
            if not results:
                return None
            
            # Preparar dados para CSV (achatar estrutura)
            csv_data = []
            for result in results:
                row = {
                    'session_id': result.get('session_id', ''),
                    'file_path': result.get('file_path', ''),
                    'file_name': result.get('file_name', ''),
                    'file_size': result.get('file_size', 0),
                    'file_type': result.get('file_type', ''),
                    'analysis_type': result.get('analysis_type', ''),
                    'success': result.get('success', False),
                    'error_message': result.get('error_message', ''),
                    'analysis_duration': result.get('analysis_duration', 0),
                    'created_at': result.get('created_at', '')
                }
                
                # Adicionar hashes
                hashes = result.get('hashes', {})
                row.update({
                    'hash_md5': hashes.get('md5', ''),
                    'hash_sha1': hashes.get('sha1', ''),
                    'hash_sha256': hashes.get('sha256', '')
                })
                
                # Adicionar alguns metadados importantes (simplificado)
                metadata = result.get('metadata', {})
                if isinstance(metadata, dict):
                    # Campos comuns
                    row['format'] = metadata.get('format', '')
                    row['dimensions'] = str(metadata.get('dimensions', ''))
                    row['duration_seconds'] = metadata.get('duration_seconds', '')
                    row['pages'] = metadata.get('pages', '')
                    row['has_exif'] = metadata.get('has_exif', '')
                
                csv_data.append(row)
            
            # Escrever CSV
            if csv_data:
                fieldnames = csv_data[0].keys()
                with open(file_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(csv_data)
            
            logger.info(f"Relatório CSV gerado: {file_path}")
            return file_path
            
        except Exception as e:
            logger.error(f"Erro ao gerar relatório CSV: {e}")
            return None
    
    def _generate_excel_report(self, 
                              session, 
                              results: List[Dict[str, Any]], 
                              statistics: Dict[str, Any],
                              output_dir: Path, 
                              timestamp: str) -> Optional[Path]:
        """Gera relatório em formato Excel"""
        try:
            file_path = output_dir / f"forensic_analysis_{timestamp}.xlsx"
            
            with pd.ExcelWriter(file_path, engine='openpyxl') as writer:
                
                # Aba de resumo
                summary_data = {
                    'Métrica': [
                        'ID da Sessão',
                        'Diretório Analisado',
                        'Total de Arquivos',
                        'Arquivos Processados',
                        'Sucessos',
                        'Falhas',
                        'Taxa de Sucesso (%)',
                        'Tamanho Total (MB)',
                        'Duração Média (s)',
                        'Data de Início',
                        'Data de Fim',
                        'Status'
                    ],
                    'Valor': [
                        session.session_id,
                        session.directory_path,
                        session.total_files,
                        session.processed_files,
                        session.successful_files,
                        session.failed_files,
                        f"{statistics.get('success_rate', 0):.1f}",
                        f"{statistics.get('total_size_mb', 0):.1f}",
                        f"{statistics.get('average_duration', 0):.2f}",
                        session.start_time.strftime("%Y-%m-%d %H:%M:%S"),
                        session.end_time.strftime("%Y-%m-%d %H:%M:%S") if session.end_time else '',
                        session.status
                    ]
                }
                
                summary_df = pd.DataFrame(summary_data)
                summary_df.to_excel(writer, sheet_name='Resumo', index=False)
                
                # Aba de resultados detalhados
                if results:
                    # Preparar dados para DataFrame
                    detailed_data = []
                    for result in results:
                        row = {
                            'Caminho do Arquivo': result.get('file_path', ''),
                            'Nome do Arquivo': result.get('file_name', ''),
                            'Tamanho (bytes)': result.get('file_size', 0),
                            'Tipo de Arquivo': result.get('file_type', ''),
                            'Tipo de Análise': result.get('analysis_type', ''),
                            'Sucesso': 'Sim' if result.get('success') else 'Não',
                            'Mensagem de Erro': result.get('error_message', ''),
                            'Duração da Análise (s)': result.get('analysis_duration', 0),
                            'Data de Criação': result.get('created_at', '')
                        }
                        
                        # Adicionar hashes
                        hashes = result.get('hashes', {})
                        row.update({
                            'Hash MD5': hashes.get('md5', ''),
                            'Hash SHA1': hashes.get('sha1', ''),
                            'Hash SHA256': hashes.get('sha256', '')
                        })
                        
                        detailed_data.append(row)
                    
                    results_df = pd.DataFrame(detailed_data)
                    results_df.to_excel(writer, sheet_name='Resultados Detalhados', index=False)
                
                # Aba de estatísticas por tipo de arquivo
                file_types = statistics.get('file_types', {})
                if file_types:
                    types_data = {
                        'Tipo de Arquivo': list(file_types.keys()),
                        'Quantidade': list(file_types.values())
                    }
                    types_df = pd.DataFrame(types_data)
                    types_df = types_df.sort_values('Quantidade', ascending=False)
                    types_df.to_excel(writer, sheet_name='Tipos de Arquivo', index=False)
                
                # Aba de arquivos maiores
                largest_files = statistics.get('largest_files', [])
                if largest_files:
                    largest_data = []
                    for file_info in largest_files:
                        largest_data.append({
                            'Caminho': file_info.get('file_path', ''),
                            'Nome': file_info.get('file_name', ''),
                            'Tamanho (bytes)': file_info.get('file_size', 0),
                            'Tamanho (MB)': f"{file_info.get('file_size', 0) / (1024*1024):.2f}"
                        })
                    
                    largest_df = pd.DataFrame(largest_data)
                    largest_df.to_excel(writer, sheet_name='Maiores Arquivos', index=False)
            
            logger.info(f"Relatório Excel gerado: {file_path}")
            return file_path
            
        except Exception as e:
            logger.error(f"Erro ao gerar relatório Excel: {e}")
            return None
    
    def _generate_html_report(self, 
                             session, 
                             results: List[Dict[str, Any]], 
                             statistics: Dict[str, Any],
                             output_dir: Path, 
                             timestamp: str) -> Optional[Path]:
        """Gera relatório em formato HTML"""
        try:
            file_path = output_dir / f"forensic_analysis_{timestamp}.html"
            
            # Template HTML
            html_template = """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Relatório de Análise Forense - {{ session.session_id }}</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1, h2 {
            color: #2c3e50;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }
        .header-info {
            background-color: #ecf0f1;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 30px;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background-color: #3498db;
            color: white;
            padding: 20px;
            border-radius: 5px;
            text-align: center;
        }
        .stat-card h3 {
            margin: 0 0 10px 0;
            font-size: 2em;
        }
        .stat-card p {
            margin: 0;
            opacity: 0.9;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 30px;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #34495e;
            color: white;
        }
        tr:nth-child(even) {
            background-color: #f2f2f2;
        }
        .success {
            color: #27ae60;
            font-weight: bold;
        }
        .error {
            color: #e74c3c;
            font-weight: bold;
        }
        .footer {
            text-align: center;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            color: #7f8c8d;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Relatório de Análise Forense</h1>
        
        <div class="header-info">
            <h2>Informações da Sessão</h2>
            <p><strong>ID da Sessão:</strong> {{ session.session_id }}</p>
            <p><strong>Diretório Analisado:</strong> {{ session.directory_path }}</p>
            <p><strong>Data de Início:</strong> {{ session.start_time.strftime("%d/%m/%Y %H:%M:%S") }}</p>
            {% if session.end_time %}
            <p><strong>Data de Fim:</strong> {{ session.end_time.strftime("%d/%m/%Y %H:%M:%S") }}</p>
            {% endif %}
            <p><strong>Status:</strong> {{ session.status }}</p>
        </div>
        
        <h2>📊 Estatísticas</h2>
        <div class="stats-grid">
            <div class="stat-card">
                <h3>{{ session.total_files }}</h3>
                <p>Total de Arquivos</p>
            </div>
            <div class="stat-card">
                <h3>{{ session.successful_files }}</h3>
                <p>Sucessos</p>
            </div>
            <div class="stat-card">
                <h3>{{ session.failed_files }}</h3>
                <p>Falhas</p>
            </div>
            <div class="stat-card">
                <h3>{{ "%.1f"|format(statistics.get('success_rate', 0)) }}%</h3>
                <p>Taxa de Sucesso</p>
            </div>
        </div>
        
        {% if statistics.get('file_types') %}
        <h2>📁 Tipos de Arquivo</h2>
        <table>
            <thead>
                <tr>
                    <th>Tipo de Arquivo</th>
                    <th>Quantidade</th>
                    <th>Percentual</th>
                </tr>
            </thead>
            <tbody>
                {% for file_type, count in statistics.get('file_types', {}).items() %}
                <tr>
                    <td>{{ file_type }}</td>
                    <td>{{ count }}</td>
                    <td>{{ "%.1f"|format((count / statistics.get('successful', 1)) * 100) }}%</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        {% endif %}
        
        <h2>📋 Resultados Detalhados (Primeiros 100)</h2>
        <table>
            <thead>
                <tr>
                    <th>Nome do Arquivo</th>
                    <th>Tipo</th>
                    <th>Tamanho</th>
                    <th>Status</th>
                    <th>Duração</th>
                </tr>
            </thead>
            <tbody>
                {% for result in results[:100] %}
                <tr>
                    <td>{{ result.get('file_name', '') }}</td>
                    <td>{{ result.get('file_type', '') }}</td>
                    <td>{{ "%.1f"|format(result.get('file_size', 0) / 1024) }} KB</td>
                    <td>
                        {% if result.get('success') %}
                            <span class="success">✅ Sucesso</span>
                        {% else %}
                            <span class="error">❌ Erro</span>
                        {% endif %}
                    </td>
                    <td>{{ "%.2f"|format(result.get('analysis_duration', 0)) }}s</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        
        <div class="footer">
            <p>Relatório gerado em {{ datetime.now().strftime("%d/%m/%Y %H:%M:%S") }} pelo Forensic Tool v2.0</p>
        </div>
    </div>
</body>
</html>
            """
            
            template = Template(html_template)
            html_content = template.render(
                session=session,
                results=results,
                statistics=statistics,
                datetime=datetime
            )
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"Relatório HTML gerado: {file_path}")
            return file_path
            
        except Exception as e:
            logger.error(f"Erro ao gerar relatório HTML: {e}")
            return None
