"""
Sistema de relatórios avançados com visualizações e análises estatísticas.

Este módulo fornece geração de relatórios sofisticados com gráficos,
estatísticas avançadas e exportação em múltiplos formatos.
"""

import json
import csv
import sqlite3
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
import logging
from dataclasses import dataclass
from collections import Counter, defaultdict

try:
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates
    from matplotlib.backends.backend_pdf import PdfPages
    import seaborn as sns
    import pandas as pd
    import numpy as np
    VISUALIZATION_AVAILABLE = True
except ImportError:
    VISUALIZATION_AVAILABLE = False
    plt = None
    sns = None
    pd = None
    np = None

from jinja2 import Template
from ..core.database import ResultsDatabase

logger = logging.getLogger(__name__)


@dataclass
class ReportConfig:
    """Configuração para geração de relatórios."""
    include_charts: bool = True
    include_statistics: bool = True
    include_security_analysis: bool = True
    include_timeline: bool = True
    chart_style: str = 'seaborn'
    color_palette: str = 'viridis'
    dpi: int = 300
    figure_size: Tuple[int, int] = (12, 8)


class AdvancedReportGenerator:
    """
    Gerador de relatórios avançados com visualizações e análises estatísticas.
    """
    
    def __init__(self, database: ResultsDatabase, config: Optional[ReportConfig] = None):
        """
        Inicializa o gerador de relatórios.
        
        Args:
            database: Instância do banco de dados
            config: Configuração para geração de relatórios
        """
        self.database = database
        self.config = config or ReportConfig()
        
        if VISUALIZATION_AVAILABLE and self.config.include_charts:
            plt.style.use(self.config.chart_style)
            sns.set_palette(self.config.color_palette)
    
    def generate_comprehensive_report(self, session_id: str, output_path: Path, 
                                    format_type: str = 'html') -> bool:
        """
        Gera um relatório abrangente para uma sessão de análise.
        
        Args:
            session_id: ID da sessão
            output_path: Caminho para salvar o relatório
            format_type: Formato do relatório ('html', 'pdf', 'json')
        
        Returns:
            bool: True se o relatório foi gerado com sucesso
        """
        try:
            logger.info(f"Gerando relatório abrangente para sessão {session_id}")
            
            # Coleta dados da sessão
            session_data = self._collect_session_data(session_id)
            if not session_data:
                logger.error(f"Sessão {session_id} não encontrada")
                return False
            
            # Gera análises estatísticas
            statistics = self._generate_advanced_statistics(session_id)
            
            # Gera análises de segurança
            security_analysis = self._generate_security_analysis(session_id)
            
            # Gera timeline de análise
            timeline_data = self._generate_timeline_analysis(session_id)
            
            # Gera gráficos (se disponível)
            charts_data = {}
            if VISUALIZATION_AVAILABLE and self.config.include_charts:
                charts_data = self._generate_charts(session_id, output_path.parent)
            
            # Compila dados do relatório
            report_data = {
                'session': session_data,
                'statistics': statistics,
                'security_analysis': security_analysis,
                'timeline': timeline_data,
                'charts': charts_data,
                'generated_at': datetime.now().isoformat(),
                'generator_version': '2.0.0'
            }
            
            # Gera relatório no formato solicitado
            if format_type.lower() == 'html':
                return self._generate_html_report(report_data, output_path)
            elif format_type.lower() == 'pdf':
                return self._generate_pdf_report(report_data, output_path)
            elif format_type.lower() == 'json':
                return self._generate_json_report(report_data, output_path)
            else:
                logger.error(f"Formato de relatório não suportado: {format_type}")
                return False
                
        except Exception as e:
            logger.error(f"Erro ao gerar relatório: {e}", exc_info=True)
            return False
    
    def _collect_session_data(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Coleta dados básicos da sessão."""
        session = self.database.get_analysis_session(session_id)
        if not session:
            return None
        
        results = self.database.get_analysis_results(session_id, limit=10000)
        
        return {
            'session_info': session.to_dict(),
            'results': results,
            'total_results': len(results)
        }
    
    def _generate_advanced_statistics(self, session_id: str) -> Dict[str, Any]:
        """Gera estatísticas avançadas da sessão."""
        results = self.database.get_analysis_results(session_id, limit=10000)
        
        if not results:
            return {}
        
        # Estatísticas básicas
        total_files = len(results)
        successful = sum(1 for r in results if r['success'])
        failed = total_files - successful
        
        # Análise por tipo de arquivo
        file_types = Counter(r['file_type'] for r in results if r['success'])
        
        # Análise por tamanho de arquivo
        file_sizes = [r['file_size'] for r in results if r['success'] and r['file_size']]
        size_stats = self._calculate_size_statistics(file_sizes)
        
        # Análise temporal
        durations = [r['analysis_duration'] for r in results if r['analysis_duration']]
        duration_stats = self._calculate_duration_statistics(durations)
        
        # Análise de extensões
        extensions = Counter()
        for result in results:
            if result['success']:
                file_path = Path(result['file_path'])
                ext = file_path.suffix.lower()
                extensions[ext or 'no_extension'] += 1
        
        # Análise de diretórios
        directories = Counter()
        for result in results:
            if result['success']:
                file_path = Path(result['file_path'])
                directories[str(file_path.parent)] += 1
        
        return {
            'summary': {
                'total_files': total_files,
                'successful': successful,
                'failed': failed,
                'success_rate': (successful / total_files * 100) if total_files > 0 else 0
            },
            'file_types': dict(file_types.most_common(20)),
            'file_sizes': size_stats,
            'analysis_duration': duration_stats,
            'extensions': dict(extensions.most_common(15)),
            'directories': dict(directories.most_common(10))
        }
    
    def _calculate_size_statistics(self, sizes: List[int]) -> Dict[str, Any]:
        """Calcula estatísticas de tamanho de arquivo."""
        if not sizes:
            return {}
        
        sizes_array = np.array(sizes) if VISUALIZATION_AVAILABLE else sizes
        
        if VISUALIZATION_AVAILABLE:
            return {
                'total_size': int(np.sum(sizes_array)),
                'average_size': float(np.mean(sizes_array)),
                'median_size': float(np.median(sizes_array)),
                'min_size': int(np.min(sizes_array)),
                'max_size': int(np.max(sizes_array)),
                'std_deviation': float(np.std(sizes_array)),
                'percentiles': {
                    '25th': float(np.percentile(sizes_array, 25)),
                    '75th': float(np.percentile(sizes_array, 75)),
                    '90th': float(np.percentile(sizes_array, 90)),
                    '95th': float(np.percentile(sizes_array, 95))
                }
            }
        else:
            # Fallback sem numpy
            sizes.sort()
            n = len(sizes)
            return {
                'total_size': sum(sizes),
                'average_size': sum(sizes) / n,
                'median_size': sizes[n // 2],
                'min_size': min(sizes),
                'max_size': max(sizes)
            }
    
    def _calculate_duration_statistics(self, durations: List[float]) -> Dict[str, Any]:
        """Calcula estatísticas de duração de análise."""
        if not durations:
            return {}
        
        if VISUALIZATION_AVAILABLE:
            durations_array = np.array(durations)
            return {
                'total_duration': float(np.sum(durations_array)),
                'average_duration': float(np.mean(durations_array)),
                'median_duration': float(np.median(durations_array)),
                'min_duration': float(np.min(durations_array)),
                'max_duration': float(np.max(durations_array)),
                'files_per_second': len(durations) / np.sum(durations_array)
            }
        else:
            # Fallback sem numpy
            total = sum(durations)
            n = len(durations)
            return {
                'total_duration': total,
                'average_duration': total / n,
                'min_duration': min(durations),
                'max_duration': max(durations),
                'files_per_second': n / total if total > 0 else 0
            }
    
    def _generate_security_analysis(self, session_id: str) -> Dict[str, Any]:
        """Gera análise de segurança da sessão."""
        results = self.database.get_analysis_results(session_id, limit=10000)
        
        security_results = [
            r for r in results 
            if r['success'] and r.get('analysis_type') == 'SecurityAnalyzer'
        ]
        
        if not security_results:
            return {'security_files_analyzed': 0}
        
        # Análise de níveis de risco
        risk_levels = Counter()
        risk_scores = []
        
        for result in security_results:
            metadata = result.get('metadata', {})
            risk_assessment = metadata.get('risk_assessment', {})
            
            risk_level = risk_assessment.get('risk_level', 'unknown')
            risk_levels[risk_level] += 1
            
            risk_score = risk_assessment.get('risk_score', 0)
            if risk_score:
                risk_scores.append(risk_score)
        
        # Análise de fatores de risco
        risk_factors = Counter()
        for result in security_results:
            metadata = result.get('metadata', {})
            risk_assessment = metadata.get('risk_assessment', {})
            factors = risk_assessment.get('risk_factors', [])
            
            for factor in factors:
                risk_factors[factor] += 1
        
        # Análise de entropy
        high_entropy_files = []
        for result in security_results:
            metadata = result.get('metadata', {})
            entropy_analysis = metadata.get('entropy_analysis', {})
            
            if entropy_analysis.get('analysis', {}).get('suspicious', False):
                high_entropy_files.append({
                    'file_path': result['file_path'],
                    'entropy': entropy_analysis.get('entropy', 0)
                })
        
        return {
            'security_files_analyzed': len(security_results),
            'risk_levels': dict(risk_levels),
            'risk_score_statistics': self._calculate_duration_statistics(risk_scores),
            'common_risk_factors': dict(risk_factors.most_common(10)),
            'high_entropy_files': high_entropy_files[:20],
            'critical_files': [
                r['file_path'] for r in security_results
                if r.get('metadata', {}).get('risk_assessment', {}).get('risk_level') == 'critical'
            ]
        }
    
    def _generate_timeline_analysis(self, session_id: str) -> Dict[str, Any]:
        """Gera análise temporal da sessão."""
        session = self.database.get_analysis_session(session_id)
        if not session:
            return {}
        
        results = self.database.get_analysis_results(session_id, limit=10000)
        
        # Análise de progresso temporal
        timeline_events = []
        
        # Evento de início
        timeline_events.append({
            'timestamp': session.start_time.isoformat(),
            'event_type': 'session_start',
            'description': f'Análise iniciada para {session.directory_path}'
        })
        
        # Eventos de análise (agrupados por hora)
        hourly_progress = defaultdict(int)
        for result in results:
            # Simula timestamp baseado na ordem (já que não temos timestamp real)
            # Em implementação real, você salvaria timestamps reais
            hourly_progress['analysis_progress'] += 1
        
        # Evento de fim
        if session.end_time:
            timeline_events.append({
                'timestamp': session.end_time.isoformat(),
                'event_type': 'session_end',
                'description': f'Análise concluída com {session.successful_files} arquivos processados'
            })
        
        return {
            'session_duration': str(session.duration) if session.duration else 'ongoing',
            'timeline_events': timeline_events,
            'progress_data': dict(hourly_progress)
        }
    
    def _generate_charts(self, session_id: str, output_dir: Path) -> Dict[str, str]:
        """Gera gráficos para o relatório."""
        if not VISUALIZATION_AVAILABLE:
            return {}
        
        charts = {}
        results = self.database.get_analysis_results(session_id, limit=10000)
        
        if not results:
            return charts
        
        # Gráfico de tipos de arquivo
        file_types = Counter(r['file_type'] for r in results if r['success'])
        if file_types:
            chart_path = output_dir / f'file_types_{session_id}.png'
            self._create_pie_chart(
                dict(file_types.most_common(10)),
                'Distribuição de Tipos de Arquivo',
                chart_path
            )
            charts['file_types'] = str(chart_path.name)
        
        # Gráfico de tamanhos de arquivo
        file_sizes = [r['file_size'] for r in results if r['success'] and r['file_size']]
        if file_sizes:
            chart_path = output_dir / f'file_sizes_{session_id}.png'
            self._create_histogram(
                file_sizes,
                'Distribuição de Tamanhos de Arquivo',
                'Tamanho (bytes)',
                'Frequência',
                chart_path
            )
            charts['file_sizes'] = str(chart_path.name)
        
        # Gráfico de análise de segurança (se disponível)
        security_results = [
            r for r in results 
            if r['success'] and r.get('analysis_type') == 'SecurityAnalyzer'
        ]
        
        if security_results:
            risk_levels = Counter()
            for result in security_results:
                metadata = result.get('metadata', {})
                risk_level = metadata.get('risk_assessment', {}).get('risk_level', 'unknown')
                risk_levels[risk_level] += 1
            
            if risk_levels:
                chart_path = output_dir / f'security_risks_{session_id}.png'
                self._create_bar_chart(
                    dict(risk_levels),
                    'Níveis de Risco de Segurança',
                    'Nível de Risco',
                    'Quantidade de Arquivos',
                    chart_path
                )
                charts['security_risks'] = str(chart_path.name)
        
        return charts
    
    def _create_pie_chart(self, data: Dict[str, int], title: str, output_path: Path):
        """Cria gráfico de pizza."""
        plt.figure(figsize=self.config.figure_size)
        
        labels = list(data.keys())
        sizes = list(data.values())
        
        plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
        plt.title(title, fontsize=16, fontweight='bold')
        plt.axis('equal')
        
        plt.tight_layout()
        plt.savefig(output_path, dpi=self.config.dpi, bbox_inches='tight')
        plt.close()
    
    def _create_histogram(self, data: List[float], title: str, xlabel: str, ylabel: str, output_path: Path):
        """Cria histograma."""
        plt.figure(figsize=self.config.figure_size)
        
        plt.hist(data, bins=30, alpha=0.7, edgecolor='black')
        plt.title(title, fontsize=16, fontweight='bold')
        plt.xlabel(xlabel, fontsize=12)
        plt.ylabel(ylabel, fontsize=12)
        plt.grid(True, alpha=0.3)
        
        plt.tight_layout()
        plt.savefig(output_path, dpi=self.config.dpi, bbox_inches='tight')
        plt.close()
    
    def _create_bar_chart(self, data: Dict[str, int], title: str, xlabel: str, ylabel: str, output_path: Path):
        """Cria gráfico de barras."""
        plt.figure(figsize=self.config.figure_size)
        
        labels = list(data.keys())
        values = list(data.values())
        
        bars = plt.bar(labels, values, alpha=0.8, edgecolor='black')
        plt.title(title, fontsize=16, fontweight='bold')
        plt.xlabel(xlabel, fontsize=12)
        plt.ylabel(ylabel, fontsize=12)
        plt.xticks(rotation=45, ha='right')
        plt.grid(True, alpha=0.3, axis='y')
        
        # Adiciona valores nas barras
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2., height,
                    f'{int(height)}', ha='center', va='bottom')
        
        plt.tight_layout()
        plt.savefig(output_path, dpi=self.config.dpi, bbox_inches='tight')
        plt.close()
    
    def _generate_html_report(self, report_data: Dict[str, Any], output_path: Path) -> bool:
        """Gera relatório em formato HTML."""
        try:
            html_template = self._get_html_template()
            template = Template(html_template)
            
            html_content = template.render(**report_data)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"Relatório HTML gerado: {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Erro ao gerar relatório HTML: {e}", exc_info=True)
            return False
    
    def _generate_pdf_report(self, report_data: Dict[str, Any], output_path: Path) -> bool:
        """Gera relatório em formato PDF."""
        try:
            # Primeiro gera HTML temporário
            temp_html = output_path.with_suffix('.temp.html')
            if not self._generate_html_report(report_data, temp_html):
                return False
            
            # Converte HTML para PDF (requer biblioteca adicional como weasyprint)
            try:
                import weasyprint
                weasyprint.HTML(filename=str(temp_html)).write_pdf(str(output_path))
                temp_html.unlink()  # Remove arquivo temporário
                logger.info(f"Relatório PDF gerado: {output_path}")
                return True
            except ImportError:
                logger.warning("weasyprint não disponível, gerando PDF simples")
                # Fallback: copia HTML como PDF (não é ideal, mas funciona)
                output_path.write_text(temp_html.read_text(encoding='utf-8'), encoding='utf-8')
                temp_html.unlink()
                return True
                
        except Exception as e:
            logger.error(f"Erro ao gerar relatório PDF: {e}", exc_info=True)
            return False
    
    def _generate_json_report(self, report_data: Dict[str, Any], output_path: Path) -> bool:
        """Gera relatório em formato JSON."""
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False, default=str)
            
            logger.info(f"Relatório JSON gerado: {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Erro ao gerar relatório JSON: {e}", exc_info=True)
            return False
    
    def _get_html_template(self) -> str:
        """Retorna template HTML para o relatório."""
        return """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Relatório Forense - {{ session.session_info.session_id }}</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }
        .header { text-align: center; border-bottom: 3px solid #007acc; padding-bottom: 20px; margin-bottom: 30px; }
        .header h1 { color: #007acc; margin: 0; font-size: 2.5em; }
        .header p { color: #666; margin: 10px 0 0 0; font-size: 1.1em; }
        .section { margin: 30px 0; }
        .section h2 { color: #333; border-left: 4px solid #007acc; padding-left: 15px; margin-bottom: 20px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 20px 0; }
        .stat-card { background: #f8f9fa; padding: 20px; border-radius: 8px; border-left: 4px solid #007acc; }
        .stat-card h3 { margin: 0 0 10px 0; color: #333; font-size: 1.1em; }
        .stat-card .value { font-size: 2em; font-weight: bold; color: #007acc; }
        .stat-card .label { color: #666; font-size: 0.9em; }
        .table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        .table th, .table td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        .table th { background-color: #007acc; color: white; font-weight: bold; }
        .table tr:hover { background-color: #f5f5f5; }
        .chart-container { text-align: center; margin: 20px 0; }
        .chart-container img { max-width: 100%; height: auto; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .risk-high { color: #dc3545; font-weight: bold; }
        .risk-medium { color: #ffc107; font-weight: bold; }
        .risk-low { color: #28a745; font-weight: bold; }
        .footer { text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; }
        .progress-bar { width: 100%; height: 20px; background-color: #e9ecef; border-radius: 10px; overflow: hidden; }
        .progress-fill { height: 100%; background-color: #007acc; transition: width 0.3s ease; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Relatório de Análise Forense</h1>
            <p>Sessão: {{ session.session_info.session_id }}</p>
            <p>Gerado em: {{ generated_at }}</p>
        </div>

        <div class="section">
            <h2>📊 Resumo da Sessão</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <h3>Total de Arquivos</h3>
                    <div class="value">{{ statistics.summary.total_files }}</div>
                    <div class="label">arquivos analisados</div>
                </div>
                <div class="stat-card">
                    <h3>Taxa de Sucesso</h3>
                    <div class="value">{{ "%.1f"|format(statistics.summary.success_rate) }}%</div>
                    <div class="label">análises bem-sucedidas</div>
                </div>
                <div class="stat-card">
                    <h3>Duração Total</h3>
                    <div class="value">{{ statistics.analysis_duration.total_duration|round(2) }}s</div>
                    <div class="label">tempo de processamento</div>
                </div>
                <div class="stat-card">
                    <h3>Performance</h3>
                    <div class="value">{{ statistics.analysis_duration.files_per_second|round(1) }}</div>
                    <div class="label">arquivos por segundo</div>
                </div>
            </div>
            
            <div class="progress-bar">
                <div class="progress-fill" style="width: {{ statistics.summary.success_rate }}%"></div>
            </div>
        </div>

        {% if charts.file_types %}
        <div class="section">
            <h2>📁 Distribuição de Tipos de Arquivo</h2>
            <div class="chart-container">
                <img src="{{ charts.file_types }}" alt="Gráfico de Tipos de Arquivo">
            </div>
        </div>
        {% endif %}

        <div class="section">
            <h2>📈 Estatísticas Detalhadas</h2>
            <table class="table">
                <thead>
                    <tr>
                        <th>Tipo de Arquivo</th>
                        <th>Quantidade</th>
                        <th>Percentual</th>
                    </tr>
                </thead>
                <tbody>
                    {% for file_type, count in statistics.file_types.items() %}
                    <tr>
                        <td>{{ file_type }}</td>
                        <td>{{ count }}</td>
                        <td>{{ "%.1f"|format((count / statistics.summary.total_files) * 100) }}%</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        {% if security_analysis.security_files_analyzed > 0 %}
        <div class="section">
            <h2>🔒 Análise de Segurança</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <h3>Arquivos Analisados</h3>
                    <div class="value">{{ security_analysis.security_files_analyzed }}</div>
                    <div class="label">análises de segurança</div>
                </div>
                {% if security_analysis.critical_files %}
                <div class="stat-card">
                    <h3>Arquivos Críticos</h3>
                    <div class="value risk-high">{{ security_analysis.critical_files|length }}</div>
                    <div class="label">requerem atenção imediata</div>
                </div>
                {% endif %}
            </div>

            {% if security_analysis.risk_levels %}
            <table class="table">
                <thead>
                    <tr>
                        <th>Nível de Risco</th>
                        <th>Quantidade</th>
                        <th>Ação Recomendada</th>
                    </tr>
                </thead>
                <tbody>
                    {% for level, count in security_analysis.risk_levels.items() %}
                    <tr>
                        <td class="{% if level == 'critical' %}risk-high{% elif level == 'high' or level == 'medium' %}risk-medium{% else %}risk-low{% endif %}">
                            {{ level.title() }}
                        </td>
                        <td>{{ count }}</td>
                        <td>
                            {% if level == 'critical' %}Não executar, isolar imediatamente
                            {% elif level == 'high' %}Evitar execução, analisar detalhadamente
                            {% elif level == 'medium' %}Cautela aumentada, scan antivírus
                            {% else %}Monitoramento normal
                            {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% endif %}
        </div>
        {% endif %}

        <div class="section">
            <h2>⏱️ Timeline da Análise</h2>
            {% for event in timeline.timeline_events %}
            <div style="margin: 10px 0; padding: 10px; background: #f8f9fa; border-radius: 5px;">
                <strong>{{ event.timestamp }}</strong> - {{ event.description }}
            </div>
            {% endfor %}
        </div>

        <div class="footer">
            <p>Relatório gerado pelo Forensic Tool v{{ generator_version }}</p>
            <p>Para mais informações, consulte a documentação oficial</p>
        </div>
    </div>
</body>
</html>
        """
