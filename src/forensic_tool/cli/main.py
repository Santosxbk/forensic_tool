"""
Interface de linha de comando para Forensic Tool
"""

import sys
import time
import signal
import json
from pathlib import Path
from typing import Optional, List, Dict, Any
import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeRemainingColumn
from rich.panel import Panel
from rich.text import Text
from rich.live import Live
from ..core import Config, AnalysisManager, ResultsDatabase, get_config, load_config, EvidenceService
from ..utils import setup_logger, get_forensic_logger
from .reports import ReportGenerator
from ..reporting import AdvancedReportGenerator, ReportConfig
from .. import __version__

console = Console()


class CLIManager:
    """Gerenciador da interface CLI"""
    
    def __init__(self):
        self.config = get_config()
        self.analysis_manager = None
        self.current_session_id = None
        self.shutdown_requested = False
        
        # Configurar handler de sinal
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handler para sinais de interrupção"""
        self.shutdown_requested = True
        console.print("\n[yellow]Interrupção recebida. Finalizando análise...[/yellow]")
        
        if self.analysis_manager and self.current_session_id:
            self.analysis_manager.cancel_analysis(self.current_session_id)
        
        sys.exit(0)
    
    def initialize(self, config_file: Optional[str] = None, log_level: str = "INFO"):
        """Inicializa o gerenciador CLI"""
        try:
            # Carregar configuração
            if config_file:
                self.config = load_config(config_file)
            
            # Configurar logging
            setup_logger(
                level=log_level,
                log_file=self.config.logging.file_path,
                console_output=False,  # CLI gerencia sua própria saída
                rich_console=False
            )
            
            # Inicializar gerenciador de análises
            self.analysis_manager = AnalysisManager(self.config)
            
            return True
            
        except Exception as e:
            console.print(f"[red]Erro na inicialização: {e}[/red]")
            return False
    
    def analyze_directory(self, 
                         directory: str,
                         output_dir: Optional[str] = None,
                         formats: List[str] = None,
                         include_hashes: bool = True,
                         max_files: Optional[int] = None) -> bool:
        """Executa análise de diretório"""
        
        if not self.analysis_manager:
            console.print("[red]Gerenciador não inicializado[/red]")
            return False
        
        try:
            directory_path = Path(directory).resolve()
            
            # Validar diretório
            if not directory_path.exists():
                console.print(f"[red]Diretório não encontrado: {directory}[/red]")
                return False
            
            if not directory_path.is_dir():
                console.print(f"[red]Caminho não é um diretório: {directory}[/red]")
                return False
            
            # Gerar ID da sessão
            session_id = f"cli_{int(time.time())}"
            self.current_session_id = session_id
            
            # Mostrar informações iniciais
            self._show_analysis_header(directory_path, session_id)
            
            # Iniciar análise
            if not self.analysis_manager.start_analysis(session_id, str(directory_path), include_hashes, max_files):
                console.print("[red]Falha ao iniciar análise[/red]")
                return False
            
            # Monitorar progresso
            success = self._monitor_analysis_progress(session_id)
            
            if success and not self.shutdown_requested:
                # Gerar relatórios
                self._generate_reports(session_id, output_dir, formats or ['json', 'csv'])
                
                # Mostrar estatísticas finais
                self._show_final_statistics(session_id)
            
            return success
            
        except Exception as e:
            console.print(f"[red]Erro na análise: {e}[/red]")
            return False
    
    def _show_analysis_header(self, directory: Path, session_id: str):
        """Mostra cabeçalho da análise"""
        header_table = Table(show_header=False, box=None, padding=(0, 1))
        header_table.add_column("Label", style="bold cyan")
        header_table.add_column("Value", style="white")
        
        header_table.add_row("🔍 Análise Forense", "Forensic Tool v2.0")
        header_table.add_row("📁 Diretório", str(directory))
        header_table.add_row("🆔 Sessão", session_id)
        header_table.add_row("⚙️  Threads", str(self.config.analysis.thread_count))
        header_table.add_row("📦 Tamanho Máximo", f"{self.config.analysis.max_file_size_mb}MB")
        
        console.print(Panel(header_table, title="[bold green]Iniciando Análise[/bold green]", border_style="green"))
    
    def _monitor_analysis_progress(self, session_id: str) -> bool:
        """Monitora progresso da análise com barra de progresso"""
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeRemainingColumn(),
            console=console,
            transient=False
        ) as progress:
            
            # Aguardar início da análise
            while True:
                analysis_progress = self.analysis_manager.get_analysis_progress(session_id)
                if analysis_progress:
                    break
                time.sleep(0.1)
            
            # Criar task de progresso
            task = progress.add_task(
                f"Analisando arquivos...",
                total=analysis_progress.total_files
            )
            
            last_update = 0
            
            # Monitorar progresso
            while True:
                if self.shutdown_requested:
                    return False
                
                current_progress = self.analysis_manager.get_analysis_progress(session_id)
                
                if not current_progress:
                    # Análise concluída ou erro
                    session = self.analysis_manager.get_analysis_session(session_id)
                    if session and session.status == "completed":
                        progress.update(task, completed=analysis_progress.total_files)
                        return True
                    else:
                        console.print("[red]Análise falhou ou foi cancelada[/red]")
                        return False
                
                # Atualizar progresso
                if current_progress.processed_files != last_update:
                    progress.update(
                        task,
                        completed=current_progress.processed_files,
                        description=f"Analisando: {current_progress.current_file}"
                    )
                    last_update = current_progress.processed_files
                
                time.sleep(0.5)
    
    def _generate_reports(self, session_id: str, output_dir: Optional[str], formats: List[str]):
        """Gera relatórios da análise"""
        try:
            output_path = Path(output_dir) if output_dir else Path.cwd()
            output_path.mkdir(parents=True, exist_ok=True)
            
            console.print("\n[cyan]Gerando relatórios...[/cyan]")
            
            report_generator = ReportGenerator(self.analysis_manager)
            generated_files = report_generator.generate_reports(session_id, output_path, formats)
            
            if generated_files:
                console.print("\n[green]✅ Relatórios gerados:[/green]")
                for file_path in generated_files:
                    console.print(f"   📄 {file_path}")
            else:
                console.print("[yellow]⚠️  Nenhum relatório foi gerado[/yellow]")
                
        except Exception as e:
            console.print(f"[red]Erro ao gerar relatórios: {e}[/red]")
    
    def _show_final_statistics(self, session_id: str):
        """Mostra estatísticas finais"""
        try:
            stats = self.analysis_manager.get_session_statistics(session_id)
            session = self.analysis_manager.get_analysis_session(session_id)
            
            if not stats or not session:
                return
            
            # Tabela de estatísticas
            stats_table = Table(title="[bold green]Estatísticas da Análise[/bold green]", box=None)
            stats_table.add_column("Métrica", style="bold cyan")
            stats_table.add_column("Valor", style="white")
            
            # Estatísticas básicas
            stats_table.add_row("📊 Total de Arquivos", str(stats.get('total_results', 0)))
            stats_table.add_row("✅ Sucessos", str(stats.get('successful', 0)))
            stats_table.add_row("❌ Falhas", str(stats.get('failed', 0)))
            stats_table.add_row("📈 Taxa de Sucesso", f"{stats.get('success_rate', 0):.1f}%")
            stats_table.add_row("⏱️  Duração Média", f"{stats.get('average_duration', 0):.2f}s")
            stats_table.add_row("💾 Tamanho Total", f"{stats.get('total_size_mb', 0):.1f}MB")
            
            if session.duration:
                duration_str = str(session.duration).split('.')[0]  # Remover microsegundos
                stats_table.add_row("🕐 Duração Total", duration_str)
            
            console.print("\n")
            console.print(stats_table)
            
            # Tipos de arquivo mais comuns
            file_types = stats.get('file_types', {})
            if file_types:
                console.print("\n[bold cyan]📁 Tipos de Arquivo Encontrados:[/bold cyan]")
                
                types_table = Table(show_header=True, header_style="bold magenta")
                types_table.add_column("Tipo", style="cyan")
                types_table.add_column("Quantidade", justify="right", style="white")
                
                # Ordenar por quantidade
                sorted_types = sorted(file_types.items(), key=lambda x: x[1], reverse=True)
                
                for file_type, count in sorted_types[:10]:  # Top 10
                    types_table.add_row(file_type, str(count))
                
                console.print(types_table)
            
        except Exception as e:
            console.print(f"[red]Erro ao mostrar estatísticas: {e}[/red]")
    
    def list_recent_sessions(self, limit: int = 10):
        """Lista sessões recentes"""
        if not self.analysis_manager:
            console.print("[red]Gerenciador não inicializado[/red]")
            return
        
        try:
            sessions = self.analysis_manager.get_recent_sessions(limit)
            
            if not sessions:
                console.print("[yellow]Nenhuma sessão encontrada[/yellow]")
                return
            
            sessions_table = Table(title="[bold green]Sessões Recentes[/bold green]")
            sessions_table.add_column("ID da Sessão", style="cyan")
            sessions_table.add_column("Diretório", style="white")
            sessions_table.add_column("Status", style="bold")
            sessions_table.add_column("Arquivos", justify="right", style="white")
            sessions_table.add_column("Data", style="dim")
            
            for session in sessions:
                status_style = {
                    'completed': 'green',
                    'running': 'yellow',
                    'error': 'red',
                    'cancelled': 'dim'
                }.get(session.get('status', 'unknown'), 'white')
                
                sessions_table.add_row(
                    session.get('session_id', ''),
                    session.get('directory_path', ''),
                    f"[{status_style}]{session.get('status', 'unknown')}[/{status_style}]",
                    f"{session.get('successful_files', 0)}/{session.get('total_files', 0)}",
                    session.get('created_at', '')[:19] if session.get('created_at') else ''
                )
            
            console.print(sessions_table)
            
        except Exception as e:
            console.print(f"[red]Erro ao listar sessões: {e}[/red]")
    
    def show_session_details(self, session_id: str):
        """Mostra detalhes de uma sessão específica"""
        if not self.analysis_manager:
            console.print("[red]Gerenciador não inicializado[/red]")
            return
        
        try:
            session = self.analysis_manager.get_analysis_session(session_id)
            stats = self.analysis_manager.get_session_statistics(session_id)
            
            if not session:
                console.print(f"[red]Sessão não encontrada: {session_id}[/red]")
                return
            
            # Informações da sessão
            session_table = Table(title=f"[bold green]Detalhes da Sessão: {session_id}[/bold green]", box=None)
            session_table.add_column("Campo", style="bold cyan")
            session_table.add_column("Valor", style="white")
            
            session_table.add_row("Diretório", session.directory_path)
            session_table.add_row("Status", session.status)
            session_table.add_row("Total de Arquivos", str(session.total_files))
            session_table.add_row("Processados", str(session.processed_files))
            session_table.add_row("Sucessos", str(session.successful_files))
            session_table.add_row("Falhas", str(session.failed_files))
            session_table.add_row("Início", session.start_time.strftime("%Y-%m-%d %H:%M:%S"))
            
            if session.end_time:
                session_table.add_row("Fim", session.end_time.strftime("%Y-%m-%d %H:%M:%S"))
            
            if session.duration:
                duration_str = str(session.duration).split('.')[0]
                session_table.add_row("Duração", duration_str)
            
            if session.error_message:
                session_table.add_row("Erro", session.error_message)
            
            console.print(session_table)
            
            # Estatísticas se disponíveis
            if stats:
                console.print(f"\n[bold cyan]📊 Estatísticas:[/bold cyan]")
                console.print(f"   Taxa de Sucesso: {stats.get('success_rate', 0):.1f}%")
                console.print(f"   Tamanho Total: {stats.get('total_size_mb', 0):.1f}MB")
                console.print(f"   Duração Média por Arquivo: {stats.get('average_duration', 0):.2f}s")
            
        except Exception as e:
            console.print(f"[red]Erro ao mostrar detalhes da sessão: {e}[/red]")
    
    def find_duplicates(self, session_id: Optional[str] = None, hash_type: str = 'sha256'):
        """Encontra arquivos duplicados"""
        if not self.analysis_manager:
            console.print("[red]Gerenciador não inicializado[/red]")
            return
        
        try:
            duplicates = self.analysis_manager.find_duplicates(session_id, hash_type)
            
            if not duplicates:
                console.print("[green]Nenhum arquivo duplicado encontrado[/green]")
                return
            
            console.print(f"[bold red]🔍 Arquivos Duplicados Encontrados ({hash_type.upper()}):[/bold red]\n")
            
            for hash_value, file_paths in duplicates.items():
                console.print(f"[bold yellow]Hash: {hash_value}[/bold yellow]")
                for path in file_paths:
                    console.print(f"   📄 {path}")
                console.print()
            
            console.print(f"[bold cyan]Total: {len(duplicates)} grupos de duplicatas[/bold cyan]")
            
        except Exception as e:
            console.print(f"[red]Erro ao encontrar duplicatas: {e}[/red]")
    
    def cleanup_old_sessions(self, days: int = 30):
        """Remove sessões antigas"""
        if not self.analysis_manager:
            console.print("[red]Gerenciador não inicializado[/red]")
            return
        
        try:
            removed_count = self.analysis_manager.cleanup_old_sessions(days)
            console.print(f"[green]✅ {removed_count} sessões antigas removidas[/green]")
            
        except Exception as e:
            console.print(f"[red]Erro na limpeza: {e}[/red]")
    
    def show_supported_formats(self):
        """Mostra formatos suportados"""
        if not self.analysis_manager:
            console.print("[red]Gerenciador não inicializado[/red]")
            return
        
        try:
            extensions = self.analysis_manager.get_supported_extensions()
            analyzers = self.analysis_manager.get_analyzer_info()
            
            # Tabela de extensões por categoria
            formats_table = Table(title="[bold green]Formatos Suportados[/bold green]")
            formats_table.add_column("Categoria", style="bold cyan")
            formats_table.add_column("Extensões", style="white")
            
            for category, exts in extensions.items():
                formats_table.add_row(category, ", ".join(sorted(exts)))
            
            console.print(formats_table)
            
            # Informações dos analisadores
            console.print("\n[bold cyan]🔧 Analisadores Disponíveis:[/bold cyan]")
            for analyzer in analyzers:
                console.print(f"   • {analyzer['name']}: {len(analyzer['extensions'])} extensões")
            
        except Exception as e:
            console.print(f"[red]Erro ao mostrar formatos: {e}[/red]")


# Instância global do gerenciador CLI
cli_manager = CLIManager()


def _evidence_service() -> EvidenceService:
    if cli_manager.analysis_manager is None:
        raise click.ClickException("Gerenciador não inicializado")
    return EvidenceService(cli_manager.analysis_manager.database)


@click.group(invoke_without_command=True)
@click.option('--config', '-c', help='Arquivo de configuração')
@click.option('--log-level', default='INFO', help='Nível de log (DEBUG, INFO, WARNING, ERROR)')
@click.option('--version', is_flag=True, help='Mostrar versão')
@click.pass_context
def main(ctx, config, log_level, version):
    """🔍 Forensic Tool - Análise Forense de Metadados"""
    
    if version:
        console.print(f"[bold green]Forensic Tool v{__version__}[/bold green]")
        console.print("Ferramenta avançada de análise forense de metadados")
        return
    
    if ctx.invoked_subcommand is None:
        console.print(ctx.get_help())
        return
    
    # Inicializar CLI manager
    if not cli_manager.initialize(config, log_level):
        sys.exit(1)


@main.group()
def case():
    """Gerencia casos forenses."""


@case.command("create")
@click.argument("name")
def case_create(name):
    """Cria um caso e exibe seu identificador."""
    try:
        record = _evidence_service().create_case(name)
        click.echo(json.dumps(record.to_dict(), ensure_ascii=False))
    except (RuntimeError, ValueError) as error:
        raise click.ClickException(str(error)) from error


@case.command("list")
def case_list():
    """Lista casos registrados."""
    click.echo(json.dumps(_evidence_service().list_cases(), ensure_ascii=False))


@main.group()
def evidence():
    """Registra e verifica evidências sem modificar o original."""


@evidence.command("register")
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--case", "case_id", required=True, help="Identificador do caso")
@click.option("--reason", default="triagem", show_default=True)
@click.option("--operator", default="unknown", show_default=True)
def evidence_register(path, case_id, reason, operator):
    """Registra uma evidência e calcula SHA-256 antes do processamento."""
    try:
        record = _evidence_service().register(path, case_id, reason, operator)
        click.echo(json.dumps(record.to_dict(), ensure_ascii=False))
    except (FileNotFoundError, KeyError, ValueError, RuntimeError, OSError) as error:
        raise click.ClickException(str(error)) from error


@evidence.command("verify")
@click.argument("evidence_id")
def evidence_verify(evidence_id):
    """Recalcula SHA-256 e informa se coincide com o valor registrado."""
    try:
        click.echo(json.dumps(_evidence_service().verify(evidence_id), ensure_ascii=False))
    except (KeyError, OSError) as error:
        raise click.ClickException(str(error)) from error


@evidence.command("history")
@click.argument("evidence_id")
def evidence_history(evidence_id):
    """Exibe os eventos append-only da cadeia de custódia."""
    try:
        click.echo(json.dumps(_evidence_service().history(evidence_id), ensure_ascii=False))
    except KeyError as error:
        raise click.ClickException(str(error)) from error


@main.command("version")
def version_command():
    """Exibe a versão instalada da ferramenta."""
    click.echo(f"Forensic Tool {__version__}")


@main.command()
@click.argument('directory', type=click.Path(exists=True, file_okay=False, dir_okay=True))
@click.option('--output', '-o', help='Diretório de saída para relatórios')
@click.option('--formats', '-f', default='json,csv', help='Formatos de relatório (json,csv,excel,html)')
@click.option('--no-hashes', is_flag=True, help='Não calcular hashes')
@click.option('--max-files', type=int, help='Número máximo de arquivos a processar')
def analyze(directory, output, formats, no_hashes, max_files):
    """Analisa um diretório em busca de metadados forenses"""
    
    format_list = [f.strip() for f in formats.split(',')]
    include_hashes = not no_hashes
    
    success = cli_manager.analyze_directory(
        directory=directory,
        output_dir=output,
        formats=format_list,
        include_hashes=include_hashes,
        max_files=max_files
    )
    
    if not success:
        sys.exit(1)


@main.command()
@click.option('--limit', '-l', default=10, help='Número de sessões a mostrar')
def sessions(limit):
    """Lista sessões de análise recentes"""
    cli_manager.list_recent_sessions(limit)


@main.command()
@click.argument('session_id')
def details(session_id):
    """Mostra detalhes de uma sessão específica"""
    cli_manager.show_session_details(session_id)


@main.command()
@click.option('--session', '-s', help='ID da sessão (todas se não especificado)')
@click.option('--hash-type', default='sha256', help='Tipo de hash (md5, sha1, sha256)')
def duplicates(session, hash_type):
    """Encontra arquivos duplicados"""
    cli_manager.find_duplicates(session, hash_type)


@main.command()
@click.option('--days', default=30, help='Idade em dias para remoção')
def cleanup(days):
    """Remove sessões antigas do banco de dados"""
    cli_manager.cleanup_old_sessions(days)


@main.command()
def formats():
    """Mostra formatos de arquivo suportados"""
    cli_manager.show_supported_formats()


if __name__ == '__main__':
    main()
