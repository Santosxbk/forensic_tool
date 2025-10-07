Dentro de um diretório `docs`, crie um arquivo `architecture.md` que detalhe a arquitetura da aplicação. Use diagramas (Mermaid ou D2) para ilustrar os componentes e o fluxo de dados. Seções recomendadas:

*   **Visão Geral da Arquitetura:** Uma explicação de alto nível da arquitetura escolhida (ex: arquitetura em camadas, modular).
*   **Diagrama de Componentes:** Um diagrama mostrando os principais componentes da aplicação (CLI, Gerenciador de Análise, Analisadores, Banco de Dados, etc.) e como eles se interconectam.
*   **Fluxo de Dados:** Um diagrama de sequência ou fluxo de dados que ilustre o processo de uma análise, desde o comando do usuário até o armazenamento dos resultados.
*   **Componentes Detalhados:**
    *   **CLI (`cli/`):** Explique como a interface de linha de comando é construída (usando `click` e `rich`) e como ela interage com o `AnalysisManager`.
    *   **Core (`core/`):** Descreva os componentes centrais:
        *   `AnalysisManager`: O orquestrador principal.
        *   `ResultsDatabase`: A camada de persistência.
        *   `Config`: O sistema de configuração.
    *   **Analisadores (`analyzers/`):** Explique o padrão de design usado (ex: Strategy Pattern com uma classe base `BaseAnalyzer`) e como novos analisadores podem ser adicionados.
    *   **Utilitários (`utils/`):** Descreva os módulos utilitários e suas responsabilidades.
*   **Decisões de Design:** Justifique as principais decisões de arquitetura, como a escolha do banco de dados, o uso de concorrência, etc.
