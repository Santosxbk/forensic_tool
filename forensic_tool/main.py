#!/usr/bin/env python3
"""
Ferramenta completa para análise forense de metadados
"""

import os
import sys
import argparse
import logging
import time
import webbrowser
import subprocess
import importlib
from pathlib import Path

def install_dependencies():
    """Verifica e instala dependências automaticamente"""
    print("🔍 Verificando dependências...")
    
    dependencies = {
        'PIL': 'pillow',
        'PyPDF2': 'pypdf2',
        'docx': 'python-docx',
        'openpyxl': 'openpyxl',
        'pptx': 'python-pptx',
        'mutagen': 'mutagen',
        'cv2': 'opencv-python',
        'magic': 'python-magic',
        'pandas': 'pandas',
        'tqdm': 'tqdm',
        'numpy': 'numpy'
    }
    
    missing_deps = []
    
    for module, package in dependencies.items():
        try:
            importlib.import_module(module)
            print(f"✅ {package} já instalado")
        except ImportError:
            print(f"❌ {package} não encontrado")
            missing_deps.append(package)
    
    if missing_deps:
        print(f"\n📦 Instalando {len(missing_deps)} dependências...")
        try:
            # Atualizar pip primeiro
            subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "pip"])
            
            # Instalar dependências
            for package in missing_deps:
                print(f"📥 Instalando {package}...")
                subprocess.check_call([sys.executable, "-m", "pip", "install", package])
            
            print("✅ Todas as dependências foram instaladas com sucesso!")
            
            # Verificar novamente após instalação
            for module, package in dependencies.items():
                try:
                    importlib.import_module(module)
                    print(f"✅ {package} verificado")
                except ImportError as e:
                    print(f"❌ Falha ao instalar {package}: {e}")
                    return False
                    
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"❌ Erro durante a instalação: {e}")
            print("\n💡 Tente instalar manualmente:")
            print("pip install pillow pypdf2 python-docx openpyxl python-pptx")
            print("pip install mutagen opencv-python python-magic pandas tqdm numpy")
            return False
        except Exception as e:
            print(f"❌ Erro inesperado: {e}")
            return False
    else:
        print("✅ Todas as dependências estão instaladas!")
        return True

# Verificar dependências antes de importar módulos locais
if not install_dependencies():
    print("\n❌ Não foi possível instalar todas as dependências.")
    print("💡 Execute manualmente: pip install -r requirements.txt")
    sys.exit(1)

# Agora importar módulos locais
try:
    from forensic_analyzer import ForensicAnalyzer, AnalysisManager
    from web_server import ForensicWebServer
    from auth_manager import AuthManager
    from database import ResultsDatabase
except ImportError as e:
    print(f"❌ Erro ao importar módulos: {e}")
    print("📦 Certifique-se de que todos os arquivos estão no mesmo diretório")
    sys.exit(1)

def setup_logging():
    """Configura o sistema de logging"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('forensic_tool.log', encoding='utf-8'),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger('ForensicTool')

def run_cli_analysis(args, logger):
    """Executa análise em modo linha de comando"""
    print(f"🔍 INICIANDO ANÁLISE FORENSE - MODO CLI")
    print("=" * 60)
    
    folder_path = Path(args.cli)
    if not folder_path.exists():
        print(f"❌ ERRO: Diretório não encontrado: {args.cli}")
        sys.exit(1)
    
    analyzer = ForensicAnalyzer()
    analysis_manager = AnalysisManager()
    
    # Contar arquivos
    logger.info(f"Contando arquivos em {folder_path}")
    print("📁 Contando arquivos...")
    total_files = analysis_manager.count_supported_files(folder_path)
    
    if total_files == 0:
        print("❌ Nenhum arquivo suportado encontrado!")
        sys.exit(1)
    
    print(f"📊 Total de arquivos encontrados: {total_files}")
    print(f"⚡ Threads: {args.threads}")
    print(f"📦 Tamanho máximo: {args.max_size}MB")
    print("=" * 60)
    
    # Criar ID de análise
    analysis_id = f"cli_{int(time.time())}"
    
    # Executar análise
    if analysis_manager.start_analysis(analysis_id, str(folder_path)):
        print("🔄 Analisando arquivos...")
        
        # Aguardar conclusão
        while True:
            status = analysis_manager.get_analysis_status(analysis_id)
            if status and status['status'] in ['completed', 'error']:
                break
            time.sleep(2)
            
            # Mostrar progresso
            if status:
                processed = status['processed_files']
                total = status['total_files']
                progress = (processed / total) * 100 if total > 0 else 0
                print(f"📊 Progresso: {processed}/{total} ({progress:.1f}%)")
        
        # Gerar relatórios
        generate_cli_reports(analysis_manager, analysis_id, args, logger)
        print("🎉 ANÁLISE CONCLUÍDA COM SUCESSO!")
    else:
        print("❌ Falha ao iniciar análise!")
        sys.exit(1)

def generate_cli_reports(analysis_manager, analysis_id, args, logger):
    """Gera relatórios no modo CLI"""
    import json
    import pandas as pd
    from datetime import datetime
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = Path(args.output) if args.output else Path.cwd()
    output_dir.mkdir(exist_ok=True)
    
    # Obter estatísticas
    stats = analysis_manager.get_analysis_stats(analysis_id)
    successful = stats['successful']
    total = stats['total_files']
    failed = stats['failed']
    
    print("\n📈 ESTATÍSTICAS DA ANÁLISE:")
    print(f"   ✅ Análises bem-sucedidas: {successful}")
    print(f"   ❌ Análises com erro: {failed}")
    print(f"   📦 Total processado: {total}")
    
    # Obter resultados
    results = analysis_manager.get_analysis_results(analysis_id, limit=total)
    
    formats = args.formato.split(',') if args.formato else ['json', 'csv']
    
    if 'json' in formats or 'todos' in formats:
        try:
            json_path = output_dir / f"metadados_forense_{timestamp}.json"
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(results, f, ensure_ascii=False, indent=2, default=str)
            print(f"   💾 JSON: {json_path}")
        except Exception as e:
            print(f"   ❌ Erro ao salvar JSON: {e}")
    
    if 'csv' in formats or 'todos' in formats:
        try:
            csv_path = output_dir / f"relatorio_forense_{timestamp}.csv"
            if results:
                # Criar DataFrame simplificado
                flat_results = []
                for result in results:
                    flat_result = {
                        'Nome_Arquivo': result.get('Nome_Arquivo', ''),
                        'Caminho_Absoluto': result.get('Caminho_Absoluto', ''),
                        'Tamanho_Bytes': result.get('Tamanho_Bytes', 0),
                        'Extensao': result.get('Extensao', ''),
                        'Tipo': result.get('Tipo', ''),
                        'Analise_Concluida': result.get('Analise_Concluida', False)
                    }
                    flat_results.append(flat_result)
                
                df = pd.DataFrame(flat_results)
                df.to_csv(csv_path, index=False, encoding='utf-8-sig')
                print(f"   💾 CSV: {csv_path}")
            else:
                print("   ⚠️  Nenhum dado para salvar em CSV")
        except Exception as e:
            print(f"   ❌ Erro ao salvar CSV: {e}")
    
    if 'excel' in formats or 'todos' in formats:
        try:
            excel_path = output_dir / f"analise_forense_{timestamp}.xlsx"
            if results:
                flat_results = []
                for result in results:
                    flat_result = {
                        'Nome_Arquivo': result.get('Nome_Arquivo', ''),
                        'Caminho_Absoluto': result.get('Caminho_Absoluto', ''),
                        'Tamanho_Bytes': result.get('Tamanho_Bytes', 0),
                        'Extensao': result.get('Extensao', ''),
                        'Tipo': result.get('Tipo', ''),
                        'Analise_Concluida': result.get('Analise_Concluida', False)
                    }
                    flat_results.append(flat_result)
                
                df = pd.DataFrame(flat_results)
                with pd.ExcelWriter(excel_path, engine='openpyxl') as writer:
                    df.to_excel(writer, index=False, sheet_name='Metadados')
                    
                    # Adicionar estatísticas
                    stats_data = {
                        'Métrica': ['Total Arquivos', 'Sucessos', 'Erros', 'Taxa de Sucesso'],
                        'Valor': [
                            total, 
                            successful, 
                            failed, 
                            f"{(successful/total)*100:.1f}%" if total > 0 else "0%"
                        ]
                    }
                    stats_df = pd.DataFrame(stats_data)
                    stats_df.to_excel(writer, index=False, sheet_name='Estatísticas')
                
                print(f"   💾 Excel: {excel_path}")
            else:
                print("   ⚠️  Nenhum dado para salvar em Excel")
        except Exception as e:
            print(f"   ❌ Erro ao salvar Excel: {e}")

def setup_arg_parser():
    """Configura o parser de argumentos"""
    parser = argparse.ArgumentParser(
        description="🔍 Script Forense Avançado - Interface Web Automática",
        add_help=False
    )
    
    # Grupo para modo de execução
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument('--gui', action='store_true',
                          help='Iniciar interface web')
    mode_group.add_argument('--cli', metavar='CAMINHO', type=str,
                          help='Modo linha de comando para análise rápida')
    
    # Opções do servidor web
    server_group = parser.add_argument_group('Opções do Servidor Web')
    server_group.add_argument('--port', type=int, default=8000,
                            help='Porta do servidor web (padrão: 8000)')
    server_group.add_argument('--host', type=str, default='localhost',
                            help='Host do servidor web (padrão: localhost)')
    server_group.add_argument('--no-browser', action='store_true',
                            help='Não abrir navegador automaticamente')
    server_group.add_argument('--auth', action='store_true',
                            help='Habilitar autenticação por token')
    server_group.add_argument('--allowed-origins', type=str, 
                            default='http://localhost:8000,http://127.0.0.1:8000',
                            help='Origens permitidas para CORS')
    
    # Opções da análise CLI
    analysis_group = parser.add_argument_group('Opções de Análise (CLI)')
    analysis_group.add_argument('--threads', type=int, default=4,
                              help='Número de threads para análise (padrão: 4)')
    analysis_group.add_argument('--max-size', type=int, default=1024,
                              help='Tamanho máximo de arquivo em MB (padrão: 1024)')
    analysis_group.add_argument('--formato', type=str, default='json,csv',
                              help='Formatos de saída: json,csv,excel,todos')
    analysis_group.add_argument('--output', type=str, default='',
                              help='Diretório de saída para relatórios')
    
    # Opções gerais
    general_group = parser.add_argument_group('Opções Gerais')
    general_group.add_argument('--help', '-h', action='help',
                              help='Mostrar esta mensagem de ajuda')
    general_group.add_argument('--version', action='version', 
                              version='Script Forense 2.0',
                              help='Mostrar versão')
    
    return parser

def main():
    """Função principal"""
    logger = setup_logging()
    parser = setup_arg_parser()
    args = parser.parse_args()
    
    # Verificar se nenhum argumento foi passado
    if len(sys.argv) == 1:
        parser.print_help()
        print("\n" + "="*60)
        print("💡 DICA: Use --gui para interface web ou --cli CAMINHO para análise direta")
        print("="*60)
        return
    
    # Modo GUI (Web)
    if args.gui:
        print("🚀 INICIANDO INTERFACE WEB FORENSE...")
        print("="*50)
        
        try:
            # Configurar autenticação
            auth_manager = AuthManager(require_auth=args.auth)
            auth_manager.load_tokens()
            
            # Configurar origens permitidas
            allowed_origins = [origin.strip() for origin in args.allowed_origins.split(',')]
            
            # Iniciar servidor
            server = ForensicWebServer(
                host=args.host,
                port=args.port,
                auth_manager=auth_manager,
                allowed_origins=allowed_origins
            )
            
            if server.start():
                # Abrir navegador se não foi desativado
                if not args.no_browser:
                    url = f"http://{args.host}:{args.port}"
                    print(f"🌐 Abrindo navegador: {url}")
                    webbrowser.open(url)
                
                print("🛑 Use Ctrl+C para parar o servidor")
                
                try:
                    # Manter o servidor rodando
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    print("\n🛑 Parando servidor...")
                    server.stop()
            else:
                print("❌ Falha ao iniciar servidor web!")
                sys.exit(1)
                
        except Exception as e:
            logger.error(f"Erro no modo GUI: {e}")
            print(f"❌ Erro: {e}")
            sys.exit(1)
    
    # Modo CLI
    elif args.cli:
        try:
            run_cli_analysis(args, logger)
        except Exception as e:
            logger.error(f"Erro no modo CLI: {e}")
            print(f"❌ Erro na análise: {e}")
            sys.exit(1)
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
