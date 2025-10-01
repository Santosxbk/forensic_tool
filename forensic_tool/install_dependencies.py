#!/usr/bin/env python3
"""
SCRIPT DE INSTALAÇÃO DE DEPENDÊNCIAS
Instala automaticamente todas as dependências necessárias
"""

import sys
import subprocess
import importlib
import platform

def check_and_install_dependencies():
    """Verifica e instala dependências com feedback detalhado"""
    
    print("🔍 SCRIPT FORENSE - VERIFICAÇÃO DE DEPENDÊNCIAS")
    print("=" * 50)
    
    # Mapeamento de módulos para pacotes pip
    dependencies = {
        'PIL': 'pillow',           # Análise de imagens
        'PyPDF2': 'pypdf2',        # PDF metadata
        'docx': 'python-docx',     # Documentos Word
        'openpyxl': 'openpyxl',    # Planilhas Excel
        'pptx': 'python-pptx',     # Apresentações PowerPoint
        'mutagen': 'mutagen',      # Metadados de áudio
        'cv2': 'opencv-python',    # Análise de vídeo
        'magic': 'python-magic',   # Detecção MIME
        'pandas': 'pandas',        # Exportação de dados
        'tqdm': 'tqdm',           # Barras de progresso
        'numpy': 'numpy'          # Processamento numérico
    }
    
    # Verificar sistema operacional
    system = platform.system().lower()
    print(f"💻 Sistema detectado: {platform.system()} {platform.release()}")
    print(f"🐍 Python: {sys.version}")
    print()
    
    missing_deps = []
    installed_deps = []
    
    # Verificar cada dependência
    for module, package in dependencies.items():
        try:
            importlib.import_module(module)
            print(f"✅ {package:20} -> Já instalado")
            installed_deps.append(package)
        except ImportError:
            print(f"❌ {package:20} -> Não encontrado")
            missing_deps.append(package)
    
    print(f"\n📊 RESUMO: {len(installed_deps)} instaladas, {len(missing_deps)} faltando")
    
    if not missing_deps:
        print("🎉 Todas as dependências estão instaladas! O script pode ser executado.")
        return True
    
    # Instalar dependências faltantes
    print(f"\n📦 Instalando {len(missing_deps)} dependências...")
    print("-" * 50)
    
    try:
        # Atualizar pip primeiro
        print("🔄 Atualizando pip...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "pip"], 
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Instalar cada pacote faltante
        for i, package in enumerate(missing_deps, 1):
            print(f"📥 [{i}/{len(missing_deps)}] Instalando {package}...")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", package],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                print(f"   ✅ {package} instalado com sucesso")
                installed_deps.append(package)
            except subprocess.CalledProcessError:
                print(f"   ❌ Falha ao instalar {package}")
                # Tentar instalação sem silenciar para ver o erro
                try:
                    subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                    print(f"   ✅ {package} instalado na segunda tentativa")
                    installed_deps.append(package)
                except subprocess.CalledProcessError as e:
                    print(f"   💥 Erro crítico ao instalar {package}")
                    missing_deps.remove(package)
                    continue
        
        # Verificação final
        print("\n🔍 Verificando instalações...")
        final_missing = []
        for module, package in dependencies.items():
            try:
                importlib.import_module(module)
                print(f"✅ {package:20} -> Verificado")
            except ImportError:
                print(f"❌ {package:20} -> Ainda faltando")
                final_missing.append(package)
        
        if final_missing:
            print(f"\n⚠️  Atenção: {len(final_missing)} dependências não puderam ser instaladas:")
            for package in final_missing:
                print(f"   - {package}")
            print("\n💡 Soluções:")
            print("   1. Execute como administrador: sudo python main.py")
            print("   2. Instale manualmente: pip install NOME_DO_PACOTE")
            print("   3. Use ambiente virtual")
            return False
        else:
            print(f"\n🎉 Todas as {len(dependencies)} dependências foram instaladas com sucesso!")
            return True
            
    except Exception as e:
        print(f"💥 Erro durante a instalação: {e}")
        print("\n🛠️  Instalação manual:")
        print("pip install pillow pypdf2 python-docx openpyxl python-pptx")
        print("pip install mutagen opencv-python python-magic pandas tqdm numpy")
        return False

def main():
    """Função principal do script de instalação"""
    if check_and_install_dependencies():
        print("\n" + "="*50)
        print("🚀 Agora você pode executar o script forense!")
        print("💡 Comandos:")
        print("   python main.py --gui          # Interface web")
        print("   python main.py --cli /caminho # Análise direta")
        print("="*50)
    else:
        print("\n❌ Não foi possível instalar todas as dependências.")
        sys.exit(1)

if __name__ == "__main__":
    main()
