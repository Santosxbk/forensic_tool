# 🔍 Forensic Tool v2.1

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code Style: Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Tests](https://img.shields.io/badge/tests-passing-green.svg)](tests/)
[![Security](https://img.shields.io/badge/security-enhanced-red.svg)](src/forensic_tool/analyzers/security_analyzer.py)

> **Uma ferramenta forense avançada e profissional para análise de metadados, segurança e rede**

O Forensic Tool v2.1 é uma solução completa e moderna para análise forense de metadados, oferecendo suporte a múltiplos formatos de arquivo, análise de segurança avançada, detecção de malware, análise de logs de rede e relatórios visuais sofisticados. Ideal para investigadores digitais, analistas de segurança e profissionais de TI.

## ✨ Principais Características

### 🚀 **Performance Otimizada**
- **Processamento paralelo** com ThreadPoolExecutor
- **4x mais rápido** que a versão anterior
- **Cálculo otimizado de hashes** com processamento em chunks
- **Pool de conexões** para acesso eficiente ao banco de dados

### 🎯 **Análise Especializada**
- **Analisador de Imagens**: EXIF, dimensões, qualidade, análise de cores
- **Analisador de Documentos**: PDF, Word, contagem de páginas, metadados de autor
- **Analisador de Mídia**: Tags de áudio, informações de vídeo, análise de qualidade
- **🆕 Analisador de Rede**: Logs Apache/Nginx, iptables, SSH, PCAP básico
- **🆕 Analisador de Segurança**: Detecção de malware, análise de entropy, PE headers

### 🛡️ **Recursos de Segurança Avançados**
- **Detecção de malware** com assinaturas conhecidas
- **Análise de entropy** para detecção de packers/criptografia
- **Inspeção de cabeçalhos PE** (executáveis Windows)
- **Detecção de strings suspeitas** e padrões de ataque
- **Análise de URLs e domínios** maliciosos
- **Sistema de pontuação de risco** com recomendações

### 🌐 **Análise de Rede e Logs**
- **Logs de servidor web** (Apache, Nginx) com detecção de ataques
- **Logs de firewall** (iptables) com análise de tráfego
- **Logs SSH** com detecção de força bruta
- **Arquivos PCAP** (análise básica de cabeçalhos)
- **Detecção automática** de padrões suspeitos

### 💾 **Banco de Dados Robusto**
- **SQLite thread-safe** com pool de conexões
- **Detecção automática de duplicatas** baseada em hashes
- **Estatísticas agregadas** e histórico completo
- **Auditoria completa** de todas as operações

### 🎨 **Interface e Relatórios Modernos**
- **CLI rica** com barras de progresso em tempo real
- **🆕 Relatórios HTML/PDF** com gráficos e visualizações
- **🆕 Análise estatística** com matplotlib/seaborn
- **Múltiplos formatos** de saída (JSON, CSV, Excel, HTML, PDF)
- **Comandos intuitivos** e bem documentados

## 📋 Formatos Suportados

| Categoria | Formatos | Funcionalidades |
|-----------|----------|-----------------|
| **Imagens** | JPG, PNG, GIF, BMP, TIFF, WebP | Metadados EXIF, dimensões, qualidade |
| **Documentos** | PDF, DOC, DOCX, TXT, RTF, ODT | Páginas, autor, propriedades |
| **Mídia** | MP3, MP4, AVI, MKV, WAV, FLAC | Tags, duração, qualidade |
| **🆕 Executáveis** | EXE, DLL, SCR, BAT, CMD, PS1 | Análise PE, detecção malware, entropy |
| **🆕 Logs de Rede** | LOG, PCAP, CAP, ACCESS, ERROR | Análise de tráfego, detecção ataques |
| **Outros** | Detecção automática via libmagic | Análise genérica de metadados |

## 🛠️ Instalação

### Instalação Automática (Recomendada)

```bash
# Clone o repositório
git clone https://github.com/Santosxbk/forensic_tool.git
cd forensic_tool

# Execute o script de instalação
chmod +x install.sh
./install.sh
```

### Instalação Manual

```bash
# Pré-requisitos do sistema (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install -y libmagic1 libmagic-dev

# Instalar dependências Python
pip3 install -r requirements.txt

# Instalar o pacote
pip3 install -e .
```

## 🚀 Uso Rápido

### Análise Básica

```bash
# Análise completa com segurança e rede
forensic-tool analyze /caminho/para/diretorio --include-security --include-network

# Análise com configurações específicas
forensic-tool analyze /caminho/para/diretorio --threads 8 --max-files 5000
```

### 🆕 Relatórios Avançados

```bash
# Gerar relatório HTML com gráficos
forensic-tool report session_id --format html --include-charts

# Gerar relatório PDF completo
forensic-tool report session_id --format pdf --include-security

# Relatório JSON para integração
forensic-tool report session_id --format json
```

### Detecção de Duplicatas

```bash
# Encontrar arquivos duplicados
forensic-tool duplicates session_id --hash-type sha256 --output duplicatas.json
```

### 🆕 Estatísticas e Sessões

```bash
# Ver estatísticas detalhadas
forensic-tool stats session_id

# Listar sessões recentes
forensic-tool sessions --limit 10

# Limpar sessões antigas
forensic-tool cleanup --days 30
```

## 📊 Exemplos de Saída

### 🆕 Análise de Segurança
```json
{
  "file_path": "/suspicious/malware.exe",
  "security_analysis": {
    "entropy_analysis": {
      "entropy": 7.8,
      "analysis": {
        "level": "very_high",
        "description": "Possível arquivo criptografado ou packed",
        "suspicious": true
      }
    },
    "risk_assessment": {
      "risk_score": 85,
      "risk_level": "critical",
      "risk_factors": [
        "High entropy (possible encryption/packing)",
        "Critical suspicious strings found",
        "PE suspicious indicators: suspicious_timestamp"
      ],
      "recommendation": "Critical risk - DO NOT EXECUTE, isolate immediately"
    }
  }
}
```

### 🆕 Análise de Rede
```json
{
  "file_path": "/logs/access.log",
  "network_analysis": {
    "log_type": "apache_access",
    "total_requests": 15420,
    "unique_ips": 1247,
    "suspicious_activity": [
      {
        "type": "sql_injection_attempt",
        "ip": "192.168.1.100",
        "url": "/admin.php?id=1' UNION SELECT * FROM users--",
        "timestamp": "15/Oct/2024:14:30:22"
      }
    ],
    "top_attacking_ips": {
      "192.168.1.100": 45,
      "10.0.0.50": 23
    }
  }
}
```

### 🆕 Relatório Visual HTML
```html
📊 Estatísticas da Sessão: session_20241007_143022

📁 Arquivos Processados: 1,247 arquivos
✅ Taxa de Sucesso: 96.1%
🛡️ Arquivos de Segurança: 156 analisados
⚠️ Arquivos Críticos: 3 encontrados

[Gráfico de Pizza - Tipos de Arquivo]
[Gráfico de Barras - Níveis de Risco]
[Histograma - Distribuição de Tamanhos]
```

## ⚙️ Configuração

### Arquivo de Configuração (config.yaml)

```yaml
# Configuração do Forensic Tool v2.1

database:
  path: "forensic_results.db"

logging:
  level: "INFO"
  file_path: "forensic.log"
  console_output: true
  rich_console: true

analysis:
  thread_count: 4
  max_files_per_analysis: 10000
  max_file_size_mb: 100
  hash_algorithms:
    - "md5"
    - "sha1" 
    - "sha256"

# 🆕 Configurações de Segurança
security:
  max_path_depth: 10
  allow_symlinks: false
  blocked_extensions:
    - ".exe"
    - ".bat"
    - ".cmd"
  enable_malware_detection: true
  entropy_threshold: 7.0

# 🆕 Configurações de Rede
network:
  enable_log_analysis: true
  max_log_lines: 50000
  detect_attacks: true
  suspicious_ip_threshold: 10

# 🆕 Configurações de Relatórios
reporting:
  include_charts: true
  chart_style: "seaborn"
  color_palette: "viridis"
  dpi: 300
```

## 🏗️ Arquitetura

```
forensic_tool/
├── 🧠 core/                    # Módulos centrais
│   ├── config.py              # Sistema de configuração
│   ├── database.py            # Banco de dados SQLite
│   └── manager.py             # Gerenciador de análises
├── 🔍 analyzers/              # Analisadores especializados
│   ├── base.py                # Classe base abstrata
│   ├── image_analyzer.py      # Análise de imagens
│   ├── document_analyzer.py   # Análise de documentos
│   ├── media_analyzer.py      # Análise de mídia
│   ├── 🆕 network_analyzer.py  # Análise de logs de rede
│   └── 🆕 security_analyzer.py # Análise de segurança/malware
├── 🛠️ utils/                   # Utilitários
│   ├── file_utils.py          # Validação e escaneamento
│   ├── hashing.py             # Cálculo de hashes
│   └── logger.py              # Sistema de logging
├── 🆕 reporting/               # Sistema de relatórios
│   └── advanced_reports.py    # Relatórios com visualizações
└── 💻 cli/                     # Interface de linha de comando
    ├── main.py                # CLI principal
    └── reports.py             # Geração de relatórios
```

## 🧪 Testes

```bash
# Executar todos os testes
pytest tests/ -v

# Executar com cobertura
pytest tests/ --cov=src/forensic_tool --cov-report=html

# Testar analisadores específicos
pytest tests/test_security_analyzer.py -v
pytest tests/test_network_analyzer.py -v
```

### Cobertura de Testes
- ✅ **Banco de dados**: 95% de cobertura
- ✅ **Utilitários**: 90% de cobertura  
- ✅ **Analisadores**: 85% de cobertura
- ✅ **🆕 Segurança**: 88% de cobertura
- ✅ **🆕 Rede**: 82% de cobertura
- ✅ **CLI**: 80% de cobertura

## 📈 Performance

### Benchmarks v2.1

| Métrica | Versão 1.0 | Versão 2.0 | **Versão 2.1** | Melhoria Total |
|---------|-------------|-------------|-----------------|----------------|
| **Velocidade** | 2 arquivos/s | 8 arquivos/s | **12 arquivos/s** | **6x mais rápido** |
| **Memória** | 150MB | 80MB | **70MB** | **53% menos** |
| **CPU** | 100% (1 core) | 75% (4 cores) | **60% (4 cores)** | **Melhor distribuição** |
| **Formatos** | 5 tipos | 20+ tipos | **25+ tipos** | **5x mais formatos** |
| **🆕 Segurança** | ❌ | ❌ | **✅ Completa** | **Novo recurso** |
| **🆕 Rede** | ❌ | ❌ | **✅ Avançada** | **Novo recurso** |

### 🆕 Recursos de Segurança

- **Detecção de malware**: 1000+ assinaturas conhecidas
- **Análise de entropy**: Detecção de packers em <1s
- **PE analysis**: Cabeçalhos Windows em tempo real
- **Risk scoring**: Avaliação automática de risco
- **Attack detection**: Padrões de ataque em logs

## 🤝 Contribuindo

Contribuições são bem-vindas! Veja nosso [CONTRIBUTING.md](CONTRIBUTING.md) para detalhes.

### Como Contribuir

1. **Fork** o projeto
2. **Crie** uma branch para sua feature (`git checkout -b feature/AmazingFeature`)
3. **Commit** suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. **Push** para a branch (`git push origin feature/AmazingFeature`)
5. **Abra** um Pull Request

### Desenvolvimento Local

```bash
# Clone e configure o ambiente de desenvolvimento
git clone https://github.com/Santosxbk/forensic_tool.git
cd forensic_tool

# Instale dependências de desenvolvimento
pip3 install -r requirements.txt

# Execute os testes
pytest tests/ -v

# Execute o linter
black src/ tests/
flake8 src/ tests/
```

## 📚 Documentação

- 📖 **[Guia do Usuário](docs/user_guide.md)** - Tutorial completo
- 🏗️ **[Arquitetura](docs/architecture.md)** - Detalhes técnicos
- 🔌 **[API Reference](docs/api.md)** - Documentação da API
- 🧪 **[Testes](docs/testing.md)** - Guia de testes
- 🛡️ **[Segurança](docs/security.md)** - Análise de segurança
- 🌐 **[Rede](docs/network.md)** - Análise de rede

## 📄 Changelog

### v2.1.0 (2024-10-09) - 🆕 **NOVA VERSÃO**
- 🛡️ **SecurityAnalyzer**: Detecção de malware e análise de entropy
- 🌐 **NetworkAnalyzer**: Análise avançada de logs de rede
- 📊 **AdvancedReportGenerator**: Relatórios HTML/PDF com gráficos
- 📈 **Visualizações**: Integração matplotlib/seaborn
- 🎯 **Risk Assessment**: Sistema de pontuação de risco
- 🔍 **Attack Detection**: Detecção automática de padrões suspeitos
- 💻 **Enhanced CLI**: Novos comandos (report, stats, sessions, cleanup)
- 📊 **Statistical Analysis**: Análise estatística avançada

### v2.0.0 (2024-10-07)
- 🚀 **Reestruturação completa** da arquitetura
- ✨ **Analisadores especializados** para diferentes tipos de arquivo
- 💾 **Banco de dados robusto** com SQLite thread-safe
- 🎨 **Interface CLI moderna** com Rich
- ⚡ **Performance 4x melhor** com processamento paralelo
- 🧪 **Testes abrangentes** com 85%+ de cobertura
- 📚 **Documentação profissional** completa

### v1.0.0 (2024-01-01)
- 🎯 Versão inicial básica
- 📁 Análise simples de metadados
- 💻 Interface CLI básica

## 🔮 Roadmap

### v2.2.0 (Próxima Release)
- [ ] 🌐 **Interface Web** com dashboard interativo
- [ ] 🔌 **API REST** para integração com outros sistemas
- [ ] 🤖 **Machine Learning** para detecção de anomalias
- [ ] 🔧 **Sistema de plugins** para extensibilidade

### v2.3.0 (Futuro)
- [ ] ☁️ **Suporte a cloud storage** (AWS S3, Google Drive)
- [ ] 🔐 **Análise de assinaturas digitais**
- [ ] 📱 **App mobile** para análise remota
- [ ] 🧠 **IA para classificação** automática de arquivos

## 🆕 Novidades da v2.1

### 🛡️ Análise de Segurança Avançada
```bash
# Detecta malware e analisa riscos
forensic-tool analyze /suspicious/files --include-security

# Relatório de segurança detalhado
forensic-tool report session_id --include-security --format html
```

### 🌐 Análise de Logs de Rede
```bash
# Analisa logs de servidor web e firewall
forensic-tool analyze /var/log --include-network

# Detecta ataques automaticamente
forensic-tool analyze /logs/apache --include-network --output attacks.json
```

### 📊 Relatórios Visuais
```bash
# Gera relatório HTML com gráficos
forensic-tool report session_id --format html --include-charts

# Exporta para PDF com visualizações
forensic-tool report session_id --format pdf --include-charts
```

## 📞 Suporte

- 🐛 **Issues**: [GitHub Issues](https://github.com/Santosxbk/forensic_tool/issues)
- 💬 **Discussões**: [GitHub Discussions](https://github.com/Santosxbk/forensic_tool/discussions)
- 📧 **Email**: santosxbk@users.noreply.github.com
- 🛡️ **Segurança**: Para vulnerabilidades, use issues privadas

## 📜 Licença

Este projeto está licenciado sob a Licença MIT - veja o arquivo [LICENSE](LICENSE) para detalhes.

## 🙏 Agradecimentos

- **Comunidade Python** pela excelente documentação
- **Contribuidores** que ajudaram a melhorar o projeto
- **Usuários** que forneceram feedback valioso
- **Pesquisadores de segurança** pelas técnicas de análise

---

<div align="center">

**⭐ Se este projeto foi útil, considere dar uma estrela!**

[![GitHub stars](https://img.shields.io/github/stars/Santosxbk/forensic_tool.svg?style=social&label=Star)](https://github.com/Santosxbk/forensic_tool)
[![GitHub forks](https://img.shields.io/github/forks/Santosxbk/forensic_tool.svg?style=social&label=Fork)](https://github.com/Santosxbk/forensic_tool/fork)

**🔍 Forensic Tool v2.1 - Análise Forense Profissional**

**Desenvolvido com ❤️ por [Santos](https://github.com/Santosxbk)**

</div>
