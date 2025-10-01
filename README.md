# forensic_tool
🚀 COMO USAR:
1. Instalação:
bash

# Criar ambiente virtual (opcional)
python -m venv forensic_env
source forensic_env/bin/activate  # Linux/Mac
# ou
forensic_env\Scripts\activate    # Windows

# Instalar dependências
pip install -r requirements.txt

2. Modo Web Interface:
bash

# Interface básica
python main.py --gui

# Com autenticação
python main.py --gui --auth

# Em rede local
python main.py --gui --host 0.0.0.0 --port 8080

3. Modo Linha de Comando:
bash

# Análise rápida
python main.py --cli /caminho/para/analisar

# Com opções avançadas
python main.py --cli /caminho/analise --threads 8 --max-size 512 --formato excel,csv --output ./relatorios

4. Com autenticação:
bash

# Gerar token
export FORENSIC_AUTH_TOKEN="seu_token_secreto_aqui"

# Ou usar arquivo
echo "seu_token_secreto_aqui" > forensic_tokens.txt

✨ FUNCIONALIDADES:

✅ Análise Completa de Metadados
✅ Interface Web Moderna
✅ Processamento em Lote
✅ Exportação Múltipla (JSON/CSV/Excel)
✅ Autenticação Segura
✅ Navegação Segura
✅ Banco de Dados SQLite
✅ Progresso em Tempo Real
✅ Tratamento Robusto de Erros

O script está 100% funcional e pronto para uso! 🎉
README.md
🔍 Script Forense Avançado

Ferramenta completa para análise forense de metadados com interface web automática

https://img.shields.io/badge/Python-3.8%252B-blue
https://img.shields.io/badge/License-MIT-green
https://img.shields.io/badge/Version-2.0-orange
📋 Índice

    Visão Geral

    Características

    Instalação

    Uso Rápido

    Modo Web Interface

    Modo Linha de Comando

    Autenticação

    Formatos Suportados

    Estrutura do Projeto

    API Documentation

    Exemplos de Uso

    Solução de Problemas

    Contribuição

    Licença

🎯 Visão Geral

O Script Forense Avançado é uma ferramenta completa desenvolvida em Python para análise forense de metadados de arquivos. Oferece tanto uma interface web moderna quanto um modo linha de comando para análise rápida e eficiente.
⚡ Para quem é esta ferramenta?

    Profissionais de Forense Digital

    Analistas de Segurança

    Administradores de Sistemas

    Investigadores Digitais

    Estudantes de Cybersecurity

✨ Características
🔍 Análise de Metadados

    Imagens: EXIF, formato, dimensões, metadados de câmera

    Documentos: PDF, Word, Excel, PowerPoint, textos

    Áudio: Codecs, duração, bitrate, metatags

    Vídeo: Resolução, FPS, codecs, duração

    Arquivos Compactados: ZIP, estrutura interna

🌐 Interface Web

    Navegação segura por diretórios

    Progresso em tempo real

    Visualização interativa de resultados

    Exportação múltipla de formatos

    Design responsivo

⚡ Performance

    Processamento multi-thread

    Banco de dados SQLite para grandes volumes

    Streaming de arquivos para evitar estouro de memória

    Limites de segurança configuráveis

🔒 Segurança

    Autenticação por token opcional

    Proteção contra path traversal

    CORS configurável

    Diretórios restritos

    Logs detalhados

🚀 Instalação
Pré-requisitos

    Python 3.8 ou superior

    pip (gerenciador de pacotes Python)

1. Clone ou baixe os arquivos
bash

git clone https://github.com/seu-usuario/script-forense.git
cd script-forense

2. Instale as dependências
bash

pip install -r requirements.txt

📦 Dependências Instaladas
Biblioteca	Função
Pillow	Análise de imagens e EXIF
pypdf2	Leitura de metadados de PDF
python-docx	Análise de documentos Word
openpyxl	Processamento de planilhas Excel
python-pptx	Análise de apresentações PowerPoint
mutagen	Metadados de áudio
opencv-python	Análise de vídeos
python-magic	Detecção de tipo MIME
pandas	Exportação e análise de dados
tqdm	Barras de progresso
💡 Uso Rápido
Modo Web (Recomendado para análise interativa)
bash

python main.py --gui

Modo CLI (Para análise em lote)
bash

python main.py --cli /caminho/para/analise

🌐 Modo Web Interface
Comandos Disponíveis
bash

# Interface básica
python main.py --gui

# Servidor em rede local
python main.py --gui --host 0.0.0.0 --port 8080

# Com autenticação
python main.py --gui --auth

# Sem abrir navegador automaticamente
python main.py --gui --no-browser

# Origens CORS personalizadas
python main.py --gui --allowed-origins "http://localhost:8000,http://meusite.com"

Funcionalidades da Interface Web

    Navegação Segura

        Listagem de drives/diretórios

        Preview de arquivos

        Proteção contra caminhos perigosos

    Análise em Tempo Real

        Progresso visual com barras

        Estatísticas atualizadas

        Detalhes de processamento

    Visualização de Resultados

        Cards informativos por arquivo

        Filtros por tipo

        Paginação para grandes volumes

    Exportação

        JSON (completo)

        CSV (estruturado)

        Excel (formatado)

⌨️ Modo Linha de Comando
Sintaxe Básica
bash

python main.py --cli CAMINHO [OPÇÕES]

Opções do CLI
Opção	Descrição	Padrão
--threads N	Número de threads	4
--max-size MB	Tamanho máximo por arquivo	1024 MB
--formato TIPOS	Formatos de saída	json,csv
--output DIR	Diretório de saída	diretório atual
Exemplos Práticos
bash

# Análise básica
python main.py --cli /home/usuario/documentos

# Alta performance
python main.py --cli /caminho/analise --threads 8 --max-size 2048

# Exportação completa
python main.py --cli /caminho/analise --formato json,csv,excel --output ./relatorios

# Análise seletiva
python main.py --cli /caminho/analise --formato json

🔐 Autenticação
Métodos de Autenticação

    Variável de Ambiente (Recomendado)

bash

export FORENSIC_AUTH_TOKEN="seu_token_super_secreto_32_chars"
python main.py --gui --auth

    Arquivo de Configuração

bash

echo "seu_token_super_secreto" > forensic_tokens.txt
python main.py --gui --auth

    Geração Automática

bash

python main.py --gui --auth
# O token será gerado e exibido no console

Headers de Autenticação
http

Authorization: Bearer seu_token_super_secreto

📁 Formatos Suportados
🖼️ Imagens

    JPEG/JPG (.jpg, .jpeg) - Metadados EXIF completos

    PNG (.png) - Informações de imagem

    BMP (.bmp) - Dados básicos

    GIF (.gif) - Metadados animados

    TIFF (.tiff, .tif) - Alto suporte a metadados

    WebP (.webp) - Formatos modernos

📄 Documentos

    PDF (.pdf) - Metadados, criptografia, páginas

    Word (.docx, .doc) - Autor, datas, estatísticas

    Excel (.xlsx, .xls) - Planilhas, abas, estrutura

    PowerPoint (.pptx, .ppt) - Slides, layouts

    Texto (.txt, .rtf) - Conteúdo, estatísticas

🎵 Mídia

    Áudio (.mp3, .flac, .wav, .m4a, .aac, .ogg) - Codecs, duração, tags

    Vídeo (.mp4, .avi, .mkv, .mov, .wmv) - Resolução, FPS, codecs

📦 Arquivos

    Compactados (.zip, .rar, .7z) - Estrutura interna, conteúdo

🗂️ Estrutura do Projeto
text

script_forense/
│
├── 📄 main.py                 # Script principal e CLI
├── 🔍 forensic_analyzer.py    # Módulo de análise forense
├── 🌐 web_server.py          # Servidor web e interface
├── 🗄️ database.py            # Gerenciamento de banco SQLite
├── 🔐 auth_manager.py        # Sistema de autenticação
├── 📋 requirements.txt       # Dependências do projeto
├── 📊 forensic_results.db    # Banco de dados (gerado)
├── 📝 forensic_tokens.txt    # Tokens (gerado)
└── 📋 forensic_tool.log      # Logs da aplicação

Arquivos Gerados
Arquivo	Descrição
forensic_results.db	Banco SQLite com resultados
forensic_tool.log	Logs de operação
forensic_tokens.txt	Tokens de autenticação
metadados_forense_*.json	Exportação JSON
relatorio_forense_*.csv	Exportação CSV
analise_forense_*.xlsx	Exportação Excel
🔌 API Documentation
Endpoints Disponíveis
🚀 Iniciar Análise
http

POST /api/analyze/{caminho}

Resposta:
json

{
  "analysis_id": "web_1640995200",
  "status": "started",
  "message": "Análise iniciada com sucesso"
}

📊 Status da Análise
http

GET /api/status/{analysis_id}

Resposta:
json

{
  "analysis_id": "web_1640995200",
  "directory": "/caminho/analise",
  "total_files": 150,
  "processed_files": 45,
  "status": "running",
  "progress": 30.0
}

📋 Resultados
http

GET /api/results/{analysis_id}?limit=20&offset=0

Resposta:
json

{
  "analysis_id": "web_1640995200",
  "results": [...],
  "pagination": {
    "limit": 20,
    "offset": 0,
    "total": 150
  }
}

📈 Estatísticas
http

GET /api/stats/{analysis_id}

Resposta:
json

{
  "total_files": 150,
  "successful": 145,
  "failed": 5,
  "type_distribution": {
    "Imagem": 89,
    "PDF": 23,
    "Documento": 38
  }
}

💾 Exportação
http

GET /api/export/{analysis_id}?format=json

Download do arquivo correspondente
💻 Exemplos de Uso
Caso 1: Análise Forense Básica
bash

# Analisar documentos suspeitos
python main.py --cli /home/usuario/Downloads/suspeitos --formato json,csv --output ./relatorio_forense

Caso 2: Auditoria de Sistema
bash

# Analisar diretório de usuário com autenticação
export FORENSIC_AUTH_TOKEN="auditoria_2024_token"
python main.py --gui --auth --host 0.0.0.0 --port 8080

Caso 3: Processamento em Lote
bash

# Múltiplos diretórios com script
for dir in /data/disk1 /data/disk2 /data/disk3; do
    python main.py --cli "$dir" --threads 6 --output "/relatorios/$(basename $dir)"
done

Caso 4: Integração com Outras Ferramentas
bash

# Gerar JSON e processar com jq
python main.py --cli /caminho/analise --formato json | jq '.[] | select(.Tipo == "PDF")'

🛠️ Solução de Problemas
Problemas Comuns
❌ "Biblioteca não instalada"

Solução:
bash

# Instalar todas as dependências
pip install -r requirements.txt

# Ou instalar manualmente
pip install pillow pypdf2 python-docx openpyxl python-pptx mutagen opencv-python python-magic pandas tqdm

❌ "Permissão negada"

Solução:
bash

# No Linux/Mac
sudo python main.py --cli /caminho/restrito

# Ou alterar proprietário
sudo chown $USER /caminho/restrito

❌ "Porta já em uso"

Solução:
bash

# Usar porta diferente
python main.py --gui --port 8081

# Ou encontrar e matar processo
lsof -ti:8000 | xargs kill -9

❌ "Arquivo muito grande"

Solução:
bash

# Aumentar limite de tamanho
python main.py --cli /caminho --max-size 2048

# Ou pular arquivos grandes
python main.py --cli /caminho --max-size 512

Logs e Debug

Os logs detalhados são salvos em forensic_tool.log:
bash

# Monitorar logs em tempo real
tail -f forensic_tool.log

# Procurar erros específicos
grep -i "error" forensic_tool.log
