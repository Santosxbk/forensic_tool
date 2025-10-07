#!/bin/bash

# Script de instalação do Forensic Tool v2.0
# Autor: Santos (Refatorado)

set -e  # Sair em caso de erro

echo "🔍 Forensic Tool v2.0 - Script de Instalação"
echo "=============================================="
echo

# Verificar se Python 3.8+ está instalado
echo "📋 Verificando pré-requisitos..."
python_version=$(python3 --version 2>&1 | awk '{print $2}' | cut -d. -f1,2)
required_version="3.8"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
    echo "❌ Erro: Python 3.8 ou superior é necessário. Versão encontrada: $python_version"
    exit 1
fi

echo "✅ Python $python_version encontrado"

# Verificar se pip está instalado
if ! command -v pip3 &> /dev/null; then
    echo "❌ Erro: pip3 não encontrado. Instale o pip3 primeiro."
    exit 1
fi

echo "✅ pip3 encontrado"

# Verificar dependências do sistema (libmagic)
echo
echo "📦 Verificando dependências do sistema..."

if command -v apt-get &> /dev/null; then
    # Ubuntu/Debian
    echo "🔧 Instalando dependências do sistema (Ubuntu/Debian)..."
    sudo apt-get update
    sudo apt-get install -y libmagic1 libmagic-dev
elif command -v yum &> /dev/null; then
    # CentOS/RHEL
    echo "🔧 Instalando dependências do sistema (CentOS/RHEL)..."
    sudo yum install -y file-devel
elif command -v brew &> /dev/null; then
    # macOS
    echo "🔧 Instalando dependências do sistema (macOS)..."
    brew install libmagic
else
    echo "⚠️  Sistema não reconhecido. Certifique-se de que libmagic está instalado."
fi

# Criar ambiente virtual (opcional)
read -p "🐍 Deseja criar um ambiente virtual? (recomendado) [y/N]: " create_venv
if [[ $create_venv =~ ^[Yy]$ ]]; then
    echo "📁 Criando ambiente virtual..."
    python3 -m venv venv
    source venv/bin/activate
    echo "✅ Ambiente virtual ativado"
fi

# Instalar dependências Python
echo
echo "📦 Instalando dependências Python..."
pip3 install --upgrade pip

# Instalar dependências principais
pip3 install \
    PyPDF2 \
    python-docx \
    openpyxl \
    pillow \
    mutagen \
    opencv-python \
    rich \
    click \
    jinja2 \
    pandas \
    colorama \
    python-magic \
    pytest \
    pytest-cov

echo "✅ Dependências instaladas com sucesso"

# Instalar o pacote
echo
echo "🔧 Instalando Forensic Tool..."
pip3 install -e .

echo "✅ Forensic Tool instalado com sucesso"

# Verificar instalação
echo
echo "🧪 Testando instalação..."
if python3 -c "import forensic_tool; print('✅ Importação OK')" 2>/dev/null; then
    echo "✅ Teste de importação passou"
else
    echo "❌ Erro no teste de importação"
    exit 1
fi

# Criar diretórios necessários
echo
echo "📁 Criando diretórios..."
mkdir -p ~/.forensic_tool/logs
mkdir -p ~/.forensic_tool/reports
mkdir -p ~/.forensic_tool/config

echo "✅ Diretórios criados"

# Criar configuração padrão
echo
echo "⚙️  Criando configuração padrão..."
cat > ~/.forensic_tool/config/config.yaml << 'EOF'
# Configuração do Forensic Tool v2.0

database:
  path: "~/.forensic_tool/forensic_results.db"

logging:
  level: "INFO"
  file_path: "~/.forensic_tool/logs/forensic.log"
  max_file_size_mb: 10
  backup_count: 5
  console_output: true
  rich_console: true

analysis:
  thread_count: 4
  max_files_per_analysis: 10000
  max_file_size_mb: 100
  chunk_size: 65536
  hash_algorithms:
    - "md5"
    - "sha1" 
    - "sha256"
  supported_extensions:
    images:
      - ".jpg"
      - ".jpeg"
      - ".png"
      - ".gif"
      - ".bmp"
      - ".tiff"
      - ".webp"
    documents:
      - ".pdf"
      - ".doc"
      - ".docx"
      - ".txt"
      - ".rtf"
      - ".odt"
    media:
      - ".mp3"
      - ".mp4"
      - ".avi"
      - ".mkv"
      - ".wav"
      - ".flac"
      - ".mov"

security:
  max_path_depth: 10
  allow_symlinks: false
  blocked_extensions:
    - ".exe"
    - ".bat"
    - ".cmd"
    - ".scr"
    - ".pif"
EOF

echo "✅ Configuração padrão criada em ~/.forensic_tool/config/config.yaml"

# Criar script de linha de comando
echo
echo "🔗 Criando link para linha de comando..."
if [[ $create_venv =~ ^[Yy]$ ]]; then
    # Se usando venv, criar script wrapper
    cat > /usr/local/bin/forensic-tool << EOF
#!/bin/bash
cd "$(dirname "\$0")/../forensic_tool_restructured"
source venv/bin/activate
python3 -m forensic_tool.cli.main "\$@"
EOF
else
    # Link direto
    cat > /usr/local/bin/forensic-tool << EOF
#!/bin/bash
python3 -m forensic_tool.cli.main "\$@"
EOF
fi

chmod +x /usr/local/bin/forensic-tool
echo "✅ Comando 'forensic-tool' disponível globalmente"

# Finalização
echo
echo "🎉 Instalação concluída com sucesso!"
echo
echo "📖 Próximos passos:"
echo "   1. Execute 'forensic-tool --help' para ver as opções disponíveis"
echo "   2. Teste com: 'forensic-tool analyze /caminho/para/diretorio'"
echo "   3. Consulte a documentação em docs/ para mais informações"
echo
echo "🔧 Configuração:"
echo "   - Arquivo de config: ~/.forensic_tool/config/config.yaml"
echo "   - Logs: ~/.forensic_tool/logs/"
echo "   - Relatórios: ~/.forensic_tool/reports/"
echo
echo "✨ Forensic Tool v2.0 está pronto para uso!"
