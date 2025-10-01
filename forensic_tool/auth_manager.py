"""
MÓDULO DE AUTENTICAÇÃO
Gerenciador de autenticação seguro para a API
"""

import os
import secrets
from pathlib import Path
from typing import Set, List

class AuthManager:
    """Gerenciador de autenticação seguro"""
    
    def __init__(self, require_auth: bool = False):
        self.tokens: Set[str] = set()
        self.token_file = Path("forensic_tokens.txt")
        self.require_auth = require_auth
    
    def load_tokens(self) -> List[str]:
        """Carrega tokens de arquivo ou variável de ambiente"""
        tokens = set()
        
        # Tentar variável de ambiente primeiro
        env_token = os.getenv('FORENSIC_AUTH_TOKEN')
        if env_token:
            tokens.add(env_token.strip())
            print(f"🔑 Token carregado da variável de ambiente")
        
        # Tentar arquivo de configuração
        if self.token_file.exists():
            try:
                with open(self.token_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        token = line.strip()
                        if token and not token.startswith('#'):
                            tokens.add(token)
                print(f"🔑 Tokens carregados do arquivo: {self.token_file}")
            except Exception as e:
                print(f⚠️  Erro ao carregar tokens do arquivo: {e}")
        
        # Se autenticação é obrigatória e não há tokens, gerar um
        if self.require_auth and not tokens:
            default_token = secrets.token_urlsafe(32)
            tokens.add(default_token)
            print("🔐 AUTENTICAÇÃO OBRIGATÓRIA HABILITADA")
            print(f"📋 Token gerado: {default_token}")
            print("💡 Use este token no header Authorization: Bearer <token>")
            print("💡 Ou salve em variável: export FORENSIC_AUTH_TOKEN=<token>")
        
        self.tokens = tokens
        
        if tokens:
            print(f"✅ Autenticação configurada - {len(tokens)} token(s) carregado(s)")
        else:
            print("🔓 Modo sem autenticação")
            
        return list(tokens)
    
    def validate_token(self, token: str) -> bool:
        """Valida token de autenticação"""
        # Se não há tokens configurados e autenticação não é obrigatória, permitir
        if not self.tokens and not self.require_auth:
            return True
        
        # Se há tokens, validar
        if self.tokens:
            for valid_token in self.tokens:
                if secrets.compare_digest(token, valid_token):
                    return True
        
        # Se autenticação é obrigatória e não validou, negar
        return not self.require_auth
    
    def get_display_token(self) -> str:
        """Retorna token mascarado para exibição segura"""
        if not self.tokens:
            return "Nenhum token configurado"
        
        token = list(self.tokens)[0]
        if len(token) > 8:
            return f"{token[:4]}...{token[-4:]}"
        return "***"
    
    def is_auth_required(self) -> bool:
        """Verifica se autenticação é obrigatória"""
        return self.require_auth or bool(self.tokens)
    
    def add_token(self, token: str) -> bool:
        """Adiciona um novo token"""
        if len(token) < 16:
            return False
        
        self.tokens.add(token)
        self._save_tokens()
        return True
    
    def remove_token(self, token: str) -> bool:
        """Remove um token"""
        if token in self.tokens:
            self.tokens.remove(token)
            self._save_tokens()
            return True
        return False
    
    def _save_tokens(self):
        """Salva tokens no arquivo"""
        try:
            with open(self.token_file, 'w', encoding='utf-8') as f:
                f.write("# Tokens de autenticação - Script Forense\n")
                f.write("# Um token por linha\n")
                for token in self.tokens:
                    f.write(f"{token}\n")
        except Exception as e:
            print(f"⚠️  Erro ao salvar tokens: {e}")
    
    def generate_token(self) -> str:
        """Gera um novo token seguro"""
        token = secrets.token_urlsafe(32)
        self.tokens.add(token)
        self._save_tokens()
        return token