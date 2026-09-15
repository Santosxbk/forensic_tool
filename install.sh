#!/usr/bin/env bash

set -euo pipefail

NON_INTERACTIVE=false
VENV_DIR="${VENV_DIR:-.venv}"

for argument in "$@"; do
    case "$argument" in
        --non-interactive) NON_INTERACTIVE=true ;;
        --venv-dir=*) VENV_DIR="${argument#*=}" ;;
        -h|--help)
            printf 'Uso: %s [--non-interactive] [--venv-dir=CAMINHO]\n' "$0"
            exit 0
            ;;
        *)
            printf 'Opção desconhecida: %s\n' "$argument" >&2
            exit 2
            ;;
    esac
done

if ! command -v python3 >/dev/null 2>&1; then
    printf 'Python 3.8+ é obrigatório.\n' >&2
    exit 1
fi

python_version="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
if ! python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)'; then
    printf 'Python 3.8+ é obrigatório; encontrado %s.\n' "$python_version" >&2
    exit 1
fi

if [[ ! -d "$VENV_DIR" ]]; then
    python3 -m venv "$VENV_DIR"
fi

# shellcheck disable=SC1090
source "$VENV_DIR/bin/activate"
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -e .

mkdir -p "$HOME/.forensic_tool/logs" "$HOME/.forensic_tool/reports" "$HOME/.forensic_tool/config"
python -m forensic_tool.cli.main --version

if [[ "$NON_INTERACTIVE" == "true" ]]; then
    printf 'Instalação concluída em %s.\n' "$VENV_DIR"
else
    printf 'Instalação concluída em %s; ative com: source %s/bin/activate\n' "$VENV_DIR" "$VENV_DIR"
fi
