"""
MÓDULO DO SERVIDOR WEB
Interface web completa para análise forense
"""

import http.server
import socketserver
import json
import urllib.parse
import threading
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional
import logging

# Importar módulos locais
try:
    from forensic_analyzer import ForensicAnalyzer, AnalysisManager
    from auth_manager import AuthManager
    from database import ResultsDatabase
except ImportError:
    # Para uso standalone
    ForensicAnalyzer = None
    AnalysisManager = None
    AuthManager = None
    ResultsDatabase = None

class DirectoryNavigator:
    """Sistema de navegação segura por diretórios"""
    
    def __init__(self):
        self.current_path = Path.home()
        self.forbidden_paths = [
            Path('/proc'), Path('/sys'), Path('/dev'),
            Path('C:/Windows/System32'), Path('C:/Windows/SysWOW64'),
        ]
    
    def get_available_drives(self) -> List[Dict[str, str]]:
        """Obtém lista de drives disponíveis"""
        drives = []
        try:
            if hasattr(os, 'name') and os.name == 'nt':  # Windows
                import string
                for drive in string.ascii_uppercase:
                    drive_path = Path(f"{drive}:\\")
                    if drive_path.exists():
                        drives.append({"name": f"Disco Local ({drive}:)", "path": str(drive_path)})
            else:  # Linux/Mac
                root_path = Path("/")
                drives.append({"name": "Sistema Raiz (/)", "path": str(root_path)})
                home_path = Path.home()
                drives.append({"name": f"Usuário ({home_path.name})", "path": str(home_path)})
        except Exception as e:
            logging.error(f"Erro ao obter drives: {e}")
        
        return drives
    
    def is_path_allowed(self, path: Path) -> bool:
        """Verifica se o caminho é permitido"""
        try:
            resolved_path = path.resolve()
            
            for forbidden in self.forbidden_paths:
                try:
                    if resolved_path.is_relative_to(forbidden):
                        return False
                except ValueError:
                    if str(resolved_path).startswith(str(forbidden)):
                        return False
            
            return True
        except Exception:
            return False
    
    def list_directories(self, path: str = None) -> List[Path]:
        """Lista diretórios de forma segura"""
        if not path or path == 'root':
            return []
        
        try:
            path_obj = Path(path)
            if not path_obj.exists() or not path_obj.is_dir():
                return []
            
            if not self.is_path_allowed(path_obj):
                return []
            
            directories = []
            for item in path_obj.iterdir():
                if item.is_dir() and not item.name.startswith('.'):
                    try:
                        # Testar acesso
                        next(item.iterdir(), None)
                        directories.append(item)
                    except (PermissionError, OSError):
                        # Adicionar mesmo sem permissão de listagem
                        directories.append(item)
            
            return sorted(directories, key=lambda x: x.name.lower())
        except Exception as e:
            logging.error(f"Erro ao listar diretórios: {e}")
            return []
    
    def list_files_preview(self, path: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Lista arquivos para preview"""
        try:
            path_obj = Path(path)
            if not path_obj.exists() or not path_obj.is_dir():
                return []
            
            if not self.is_path_allowed(path_obj):
                return []
            
            files = []
            count = 0
            
            for file_path in path_obj.iterdir():
                if file_path.is_file():
                    try:
                        stat = file_path.stat()
                        files.append({
                            "name": file_path.name,
                            "size": stat.st_size,
                            "modified": stat.st_mtime,
                            "extension": file_path.suffix.lower()
                        })
                        count += 1
                        if count >= limit:
                            break
                    except (OSError, PermissionError):
                        continue
            
            return sorted(files, key=lambda x: x['name'].lower())
        except Exception as e:
            logging.error(f"Erro no preview de arquivos: {e}")
            return []

class ForensicHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    """Handler HTTP para interface web forense"""
    
    def __init__(self, *args, **kwargs):
        self.auth_manager = kwargs.pop('auth_manager', None)
        self.allowed_origins = kwargs.pop('allowed_origins', [])
        self.navigator = DirectoryNavigator()
        self.analysis_manager = AnalysisManager() if AnalysisManager else None
        super().__init__(*args, **kwargs)
    
    def log_message(self, format, *args):
        """Customiza logging do servidor"""
        logging.info(f"{self.client_address[0]} - {format % args}")
    
    def check_auth(self) -> bool:
        """Verifica autenticação"""
        if not self.auth_manager:
            return True
        return self.auth_manager.validate_token(self._get_token_from_header())
    
    def _get_token_from_header(self) -> str:
        """Extrai token do header"""
        auth_header = self.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            return auth_header[7:]
        return ""
    
    def send_cors_headers(self):
        """Envia headers CORS"""
        origin = self.headers.get('Origin', '')
        if '*' in self.allowed_origins or origin in self.allowed_origins:
            self.send_header('Access-Control-Allow-Origin', origin or '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Authorization, Content-Type')
    
    def do_OPTIONS(self):
        """Manipula requisições OPTIONS para CORS"""
        self.send_response(200)
        self.send_cors_headers()
        self.end_headers()
    
    def do_GET(self):
        """Manipula requisições GET"""
        try:
            if not self.check_auth():
                self.send_error(401, "Não autorizado")
                return
            
            path = urllib.parse.unquote(self.path)
            
            if path == '/' or path == '/index.html':
                self.serve_frontend()
            elif path.startswith('/api/'):
                self.handle_api_request(path)
            else:
                self.send_error(404, "Endpoint não encontrado")
                
        except Exception as e:
            logging.error(f"Erro na requisição GET: {e}")
            self.send_error(500, f"Erro interno: {str(e)}")
    
    def serve_frontend(self):
        """Serve a interface web"""
        html_content = self._generate_interface()
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(html_content.encode('utf-8'))))
        self.send_cors_headers()
        self.end_headers()
        self.wfile.write(html_content.encode('utf-8'))
    
    def _generate_interface(self) -> str:
        """Gera a interface HTML"""
        return """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Painel Forense - Análise de Metadados</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container { 
            max-width: 1400px; 
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .header { 
            background: linear-gradient(135deg, #2c3e50, #34495e);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .header h1 { 
            font-size: 2.5em; 
            margin-bottom: 10px;
        }
        .header p { 
            opacity: 0.9;
            font-size: 1.1em;
        }
        .content { 
            display: grid; 
            grid-template-columns: 350px 1fr;
            gap: 0;
            min-height: 600px;
        }
        .panel { 
            padding: 25px;
            background: #f8f9fa;
            border-right: 1px solid #e9ecef;
        }
        .main-content {
            padding: 25px;
            background: white;
        }
        .section { 
            background: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
        }
        h2 { color: #2c3e50; margin-bottom: 15px; }
        h3 { color: #34495e; margin-bottom: 10px; }
        
        .drive-list { 
            max-height: 200px; 
            overflow-y: auto;
            border: 1px solid #ddd;
            border-radius: 5px;
            margin-bottom: 15px;
        }
        .drive-item { 
            padding: 10px; 
            border-bottom: 1px solid #eee;
            cursor: pointer;
            transition: background 0.2s;
        }
        .drive-item:hover { background: #e3f2fd; }
        .drive-item:last-child { border-bottom: none; }
        
        .directory-tree { 
            max-height: 300px; 
            overflow-y: auto;
            border: 1px solid #ddd;
            border-radius: 5px;
            margin-bottom: 15px;
        }
        .dir-item { 
            padding: 8px 12px; 
            cursor: pointer;
            border-bottom: 1px solid #f0f0f0;
            display: flex;
            align-items: center;
        }
        .dir-item:hover { background: #f0f7ff; }
        .dir-item:before { content: '📁'; margin-right: 8px; }
        
        .analyze-btn {
            background: linear-gradient(135deg, #e74c3c, #c0392b);
            color: white;
            border: none;
            padding: 15px 25px;
            border-radius: 8px;
            cursor: pointer;
            width: 100%;
            font-size: 16px;
            font-weight: bold;
            margin: 20px 0;
            transition: transform 0.2s;
        }
        .analyze-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(231, 76, 60, 0.3);
        }
        .analyze-btn:disabled {
            background: #95a5a6;
            cursor: not-allowed;
            transform: none;
        }
        
        .progress-bar {
            width: 100%;
            height: 20px;
            background: #ecf0f1;
            border-radius: 10px;
            overflow: hidden;
            margin: 10px 0;
        }
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #2ecc71, #27ae60);
            transition: width 0.3s;
        }
        
        .results-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }
        .result-card {
            background: white;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            padding: 15px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .result-card h4 { 
            color: #2c3e50; 
            margin-bottom: 8px;
            word-break: break-all;
        }
        .result-meta {
            font-size: 0.9em;
            color: #7f8c8d;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        .stat-card {
            background: linear-gradient(135deg, #3498db, #2980b9);
            color: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
        }
        .stat-number {
            font-size: 2em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .pagination {
            display: flex;
            justify-content: center;
            margin: 20px 0;
            gap: 10px;
        }
        .pagination button {
            padding: 8px 15px;
            border: 1px solid #bdc3c7;
            background: white;
            cursor: pointer;
            border-radius: 5px;
            transition: all 0.2s;
        }
        .pagination button:hover:not(:disabled) {
            background: #3498db;
            color: white;
            border-color: #3498db;
        }
        .pagination button:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        
        .tab-container {
            margin-top: 20px;
        }
        .tabs {
            display: flex;
            border-bottom: 2px solid #ecf0f1;
            margin-bottom: 20px;
        }
        .tab {
            padding: 12px 25px;
            cursor: pointer;
            border-bottom: 3px solid transparent;
            transition: all 0.3s;
        }
        .tab.active {
            border-bottom-color: #3498db;
            color: #3498db;
            font-weight: bold;
        }
        .tab-content {
            display: none;
        }
        .tab-content.active {
            display: block;
        }
        
        .loading {
            text-align: center;
            padding: 40px;
            color: #7f8c8d;
        }
        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #3498db;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto 20px;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .error { color: #e74c3c; padding: 10px; background: #ffeaea; border-radius: 5px; margin: 10px 0; }
        .success { color: #27ae60; padding: 10px; background: #eaffea; border-radius: 5px; margin: 10px 0; }
        .warning { color: #f39c12; padding: 10px; background: #fffaea; border-radius: 5px; margin: 10px 0; }
        
        @media (max-width: 768px) {
            .content { grid-template-columns: 1fr; }
            .panel { border-right: none; border-bottom: 1px solid #e9ecef; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Painel Forense Web</h1>
            <p>Análise completa de metadados de arquivos - Interface Web</p>
        </div>
        
        <div class="content">
            <!-- Painel de Navegação -->
            <div class="panel">
                <div class="section">
                    <h3>📍 Navegação</h3>
                    <div class="drive-list" id="driveList">
                        <div class="loading">Carregando drives...</div>
                    </div>
                    
                    <div class="directory-tree" id="directoryTree">
                        <div class="loading">Selecione um drive...</div>
                    </div>
                    
                    <div id="currentPath" class="warning" style="display: none;">
                        <strong>Diretório atual:</strong> <span id="pathDisplay"></span>
                    </div>
                    
                    <button class="analyze-btn" id="analyzeBtn" disabled>
                        🔍 Analisar Diretório Selecionado
                    </button>
                </div>
                
                <div class="section">
                    <h3>📊 Análises Ativas</h3>
                    <div id="activeAnalyses">
                        <div class="warning">Nenhuma análise ativa</div>
                    </div>
                </div>
            </div>
            
            <!-- Conteúdo Principal -->
            <div class="main-content">
                <div class="tabs">
                    <div class="tab active" data-tab="results">📋 Resultados</div>
                    <div class="tab" data-tab="stats">📈 Estatísticas</div>
                    <div class="tab" data-tab="export">💾 Exportar</div>
                </div>
                
                <div class="tab-content active" id="resultsTab">
                    <div class="section">
                        <h2>Resultados da Análise</h2>
                        <div id="analysisProgress" style="display: none;">
                            <div class="progress-bar">
                                <div class="progress-fill" id="progressFill" style="width: 0%"></div>
                            </div>
                            <div id="progressText">Processando... 0%</div>
                        </div>
                        <div id="resultsContainer">
                            <div class="loading">
                                <div class="spinner"></div>
                                <p>Selecione um diretório e inicie a análise</p>
                            </div>
                        </div>
                        <div class="pagination" id="pagination" style="display: none;">
                            <button id="prevBtn">← Anterior</button>
                            <span id="pageInfo">Página 1</span>
                            <button id="nextBtn">Próxima →</button>
                        </div>
                    </div>
                </div>
                
                <div class="tab-content" id="statsTab">
                    <div class="section">
                        <h2>Estatísticas da Análise</h2>
                        <div id="statsContainer">
                            <div class="loading">
                                <p>Nenhuma estatística disponível</p>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="tab-content" id="exportTab">
                    <div class="section">
                        <h2>Exportar Resultados</h2>
                        <div id="exportContainer">
                            <div class="warning">
                                <p>Execute uma análise primeiro para exportar os resultados</p>
                            </div>
                            <div id="exportButtons" style="display: none;">
                                <button onclick="exportResults('json')" class="analyze-btn" style="background: #3498db; margin: 5px 0;">📄 Exportar JSON</button>
                                <button onclick="exportResults('csv')" class="analyze-btn" style="background: #27ae60; margin: 5px 0;">📊 Exportar CSV</button>
                                <button onclick="exportResults('excel')" class="analyze-btn" style="background: #e67e22; margin: 5px 0;">📗 Exportar Excel</button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Variáveis globais
        let currentAnalysisId = null;
        let currentPage = 1;
        const pageSize = 20;
        let currentDirectory = '';
        
        // Inicialização
        document.addEventListener('DOMContentLoaded', function() {
            loadDrives();
            setupEventListeners();
        });
        
        function setupEventListeners() {
            // Tabs
            document.querySelectorAll('.tab').forEach(tab => {
                tab.addEventListener('click', function() {
                    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
                    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
                    this.classList.add('active');
                    document.getElementById(this.dataset.tab + 'Tab').classList.add('active');
                });
            });
            
            // Paginação
            document.getElementById('prevBtn')?.addEventListener('click', prevPage);
            document.getElementById('nextBtn')?.addEventListener('click', nextPage);
            
            // Análise
            document.getElementById('analyzeBtn')?.addEventListener('click', startAnalysis);
        }
        
        async function loadDrives() {
            try {
                const response = await fetch('/api/drives');
                const drives = await response.json();
                
                const driveList = document.getElementById('driveList');
                driveList.innerHTML = '';
                
                drives.forEach(drive => {
                    const driveItem = document.createElement('div');
                    driveItem.className = 'drive-item';
                    driveItem.innerHTML = `<strong>${drive.name}</strong><br><small>${drive.path}</small>`;
                    driveItem.addEventListener('click', () => loadDirectory(drive.path));
                    driveList.appendChild(driveItem);
                });
            } catch (error) {
                document.getElementById('driveList').innerHTML = '<div class="error">Erro ao carregar drives</div>';
            }
        }
        
        async function loadDirectory(path) {
            try {
                currentDirectory = path;
                document.getElementById('pathDisplay').textContent = path;
                document.getElementById('currentPath').style.display = 'block';
                document.getElementById('analyzeBtn').disabled = false;
                
                const response = await fetch(`/api/directory/${encodeURIComponent(path)}`);
                const data = await response.json();
                
                const tree = document.getElementById('directoryTree');
                tree.innerHTML = '';
                
                // Diretórios
                data.directories.forEach(dir => {
                    const dirItem = document.createElement('div');
                    dirItem.className = 'dir-item';
                    dirItem.textContent = dir.name;
                    dirItem.addEventListener('click', () => loadDirectory(dir.path));
                    tree.appendChild(dirItem);
                });
                
                // Arquivos (preview)
                if (data.files.length > 0) {
                    const fileHeader = document.createElement('div');
                    fileHeader.className = 'dir-item';
                    fileHeader.style.background = '#f8f9fa';
                    fileHeader.textContent = `📄 ${data.files.length} arquivo(s) encontrado(s)`;
                    tree.appendChild(fileHeader);
                }
                
            } catch (error) {
                document.getElementById('directoryTree').innerHTML = '<div class="error">Erro ao carregar diretório</div>';
            }
        }
        
        async function startAnalysis() {
            if (!currentDirectory) return;
            
            try {
                document.getElementById('analyzeBtn').disabled = true;
                document.getElementById('analyzeBtn').textContent = '🔄 Iniciando análise...';
                
                const response = await fetch(`/api/analyze/${encodeURIComponent(currentDirectory)}`);
                const result = await response.json();
                
                if (result.analysis_id) {
                    currentAnalysisId = result.analysis_id;
                    document.getElementById('analyzeBtn').textContent = '📊 Análise em andamento...';
                    monitorAnalysis();
                } else {
                    throw new Error(result.message || 'Falha ao iniciar análise');
                }
                
            } catch (error) {
                document.getElementById('analyzeBtn').disabled = false;
                document.getElementById('analyzeBtn').textContent = '🔍 Analisar Diretório Selecionado';
                showError('Erro ao iniciar análise: ' + error.message);
            }
        }
        
        async function monitorAnalysis() {
            if (!currentAnalysisId) return;
            
            const checkStatus = async () => {
                try {
                    const response = await fetch(`/api/status/${currentAnalysisId}`);
                    const status = await response.json();
                    
                    if (status.status === 'completed') {
                        document.getElementById('analyzeBtn').disabled = false;
                        document.getElementById('analyzeBtn').textContent = '🔍 Analisar Diretório Selecionado';
                        document.getElementById('analysisProgress').style.display = 'none';
                        loadResults(1);
                        loadStats();
                        document.getElementById('exportButtons').style.display = 'block';
                        showSuccess('Análise concluída com sucesso!');
                    } else if (status.status === 'error') {
                        document.getElementById('analyzeBtn').disabled = false;
                        document.getElementById('analyzeBtn').textContent = '🔍 Analisar Diretório Selecionado';
                        document.getElementById('analysisProgress').style.display = 'none';
                        showError('Erro na análise: ' + (status.error || 'Erro desconhecido'));
                    } else {
                        // Ainda processando
                        const progress = status.total_files > 0 ? 
                            (status.processed_files / status.total_files) * 100 : 0;
                        
                        document.getElementById('progressFill').style.width = progress + '%';
                        document.getElementById('progressText').textContent = 
                            `Processando... ${progress.toFixed(1)}% (${status.processed_files}/${status.total_files})`;
                        document.getElementById('analysisProgress').style.display = 'block';
                        
                        setTimeout(checkStatus, 2000);
                    }
                } catch (error) {
                    console.error('Erro ao verificar status:', error);
                    setTimeout(checkStatus, 5000);
                }
            };
            
            checkStatus();
        }
        
        async function loadResults(page = 1) {
            if (!currentAnalysisId) return;
            
            try {
                const offset = (page - 1) * pageSize;
                const response = await fetch(`/api/results/${currentAnalysisId}?limit=${pageSize}&offset=${offset}`);
                const data = await response.json();
                
                displayResults(data.results);
                updatePagination(data.pagination);
                
            } catch (error) {
                showError('Erro ao carregar resultados: ' + error.message);
            }
        }
        
        function displayResults(results) {
            const container = document.getElementById('resultsContainer');
            
            if (!results || results.length === 0) {
                container.innerHTML = '<div class="warning">Nenhum resultado encontrado</div>';
                return;
            }
            
            let html = '<div class="results-grid">';
            
            results.forEach(result => {
                const success = result.Analise_Concluida ? '✅' : '❌';
                const size = formatFileSize(result.Tamanho_Bytes || 0);
                
                html += `
                    <div class="result-card">
                        <h4>${success} ${result.Nome_Arquivo}</h4>
                        <div class="result-meta">
                            <strong>Tipo:</strong> ${result.Tipo || 'Desconhecido'}<br>
                            <strong>Tamanho:</strong> ${size}<br>
                            <strong>Extensão:</strong> ${result.Extensao || 'N/A'}<br>
                            <strong>Caminho:</strong> ${result.Caminho_Absoluto || 'N/A'}<br>
                            ${result.Erro_Critico ? `<strong>Erro:</strong> ${result.Erro_Critico}` : ''}
                        </div>
                    </div>
                `;
            });
            
            html += '</div>';
            container.innerHTML = html;
        }
        
        async function loadStats() {
            if (!currentAnalysisId) return;
            
            try {
                const response = await fetch(`/api/stats/${currentAnalysisId}`);
                const stats = await response.json();
                displayStats(stats);
            } catch (error) {
                console.error('Erro ao carregar estatísticas:', error);
            }
        }
        
        function displayStats(stats) {
            const container = document.getElementById('statsContainer');
            
            let html = `
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-number">${stats.total_files}</div>
                        <div>Total de Arquivos</div>
                    </div>
                    <div class="stat-card" style="background: linear-gradient(135deg, #2ecc71, #27ae60);">
                        <div class="stat-number">${stats.successful}</div>
                        <div>Análises Bem-sucedidas</div>
                    </div>
                    <div class="stat-card" style="background: linear-gradient(135deg, #e74c3c, #c0392b);">
                        <div class="stat-number">${stats.failed}</div>
                        <div>Análises com Erro</div>
                    </div>
                </div>
            `;
            
            if (stats.type_distribution) {
                html += '<h3>Distribuição por Tipo:</h3><ul>';
                for (const [type, count] of Object.entries(stats.type_distribution)) {
                    html += `<li><strong>${type}:</strong> ${count} arquivos</li>`;
                }
                html += '</ul>';
            }
            
            container.innerHTML = html;
        }
        
        function updatePagination(pagination) {
            const paginationEl = document.getElementById('pagination');
            const pageInfo = document.getElementById('pageInfo');
            const prevBtn = document.getElementById('prevBtn');
            const nextBtn = document.getElementById('nextBtn');
            
            if (pagination.total <= pageSize) {
                paginationEl.style.display = 'none';
                return;
            }
            
            paginationEl.style.display = 'flex';
            pageInfo.textContent = `Página ${currentPage} de ${Math.ceil(pagination.total / pageSize)}`;
            prevBtn.disabled = currentPage === 1;
            nextBtn.disabled = currentPage >= Math.ceil(pagination.total / pageSize);
        }
        
        function prevPage() {
            if (currentPage > 1) {
                currentPage--;
                loadResults(currentPage);
            }
        }
        
        function nextPage() {
            currentPage++;
            loadResults(currentPage);
        }
        
        async function exportResults(format) {
            if (!currentAnalysisId) return;
            
            try {
                const response = await fetch(`/api/export/${currentAnalysisId}?format=${format}`);
                if (response.ok) {
                    const blob = await response.blob();
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `forensic_analysis_${currentAnalysisId}.${format}`;
                    document.body.appendChild(a);
                    a.click();
                    window.URL.revokeObjectURL(url);
                    document.body.removeChild(a);
                    showSuccess(`Exportação ${format.toUpperCase()} realizada com sucesso!`);
                } else {
                    throw new Error('Erro na exportação');
                }
            } catch (error) {
                showError('Erro na exportação: ' + error.message);
            }
        }
        
        // Funções utilitárias
        function formatFileSize(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }
        
        function showError(message) {
            const errorDiv = document.createElement('div');
            errorDiv.className = 'error';
            errorDiv.textContent = message;
            document.querySelector('.main-content').prepend(errorDiv);
            setTimeout(() => errorDiv.remove(), 5000);
        }
        
        function showSuccess(message) {
            const successDiv = document.createElement('div');
            successDiv.className = 'success';
            successDiv.textContent = message;
            document.querySelector('.main-content').prepend(successDiv);
            setTimeout(() => successDiv.remove(), 5000);
        }
    </script>
</body>
</html>
        """
    
    def handle_api_request(self, path: str):
        """Manipula requisições da API"""
        try:
            if path == '/api/drives':
                self.handle_drives_request()
            elif path.startswith('/api/directory/'):
                self.handle_directory_request(path)
            elif path.startswith('/api/analyze/'):
                self.handle_analyze_request(path)
            elif path.startswith('/api/status/'):
                self.handle_status_request(path)
            elif path.startswith('/api/results/'):
                self.handle_results_request(path)
            elif path.startswith('/api/stats/'):
                self.handle_stats_request(path)
            elif path.startswith('/api/export/'):
                self.handle_export_request(path)
            else:
                self.send_error(404, "Endpoint API não encontrado")
                
        except Exception as e:
            logging.error(f"Erro na API {path}: {e}")
            self.send_error(500, f"Erro na API: {str(e)}")
    
    def handle_drives_request(self):
        """Manipula requisição de lista de drives"""
        drives = self.navigator.get_available_drives()
        self.send_json_response(drives)
    
    def handle_directory_request(self, path: str):
        """Manipula requisição de listagem de diretório"""
        dir_path = path.replace('/api/directory/', '')
        if not dir_path or dir_path == 'root':
            self.send_json_response({"path": "", "directories": [], "files": []})
            return
        
        directories = self.navigator.list_directories(dir_path)
        files = self.navigator.list_files_preview(dir_path)
        
        response = {
            "path": dir_path,
            "directories": [{"name": d.name, "path": str(d)} for d in directories],
            "files": files
        }
        
        self.send_json_response(response)
    
    def handle_analyze_request(self, path: str):
        """Manipula requisição de início de análise"""
        analysis_path = path.replace('/api/analyze/', '')
        if not analysis_path:
            self.send_error(400, "Caminho não especificado")
            return
        
        if not self.analysis_manager:
            self.send_error(500, "Sistema de análise não disponível")
            return
        
        analysis_id = f"web_{int(datetime.now().timestamp())}"
        
        if self.analysis_manager.start_analysis(analysis_id, analysis_path):
            response = {
                "analysis_id": analysis_id,
                "status": "started",
                "message": "Análise iniciada com sucesso"
            }
        else:
            response = {
                "analysis_id": None,
                "status": "error",
                "message": "Falha ao iniciar análise"
            }
        
        self.send_json_response(response)
    
    def handle_status_request(self, path: str):
        """Manipula requisição de status da análise"""
        analysis_id = path.replace('/api/status/', '')
        if not self.analysis_manager:
            self.send_error(500, "Sistema de análise não disponível")
            return
        
        status = self.analysis_manager.get_analysis_status(analysis_id)
        
        if status:
            self.send_json_response(status)
        else:
            self.send_error(404, "Análise não encontrada")
    
    def handle_results_request(self, path: str):
        """Manipula requisição de resultados"""
        parts = path.replace('/api/results/', '').split('?')
        analysis_id = parts[0]
        
        if not self.analysis_manager:
            self.send_error(500, "Sistema de análise não disponível")
            return
        
        # Parse parâmetros
        limit = 20
        offset = 0
        
        if len(parts) > 1:
            params = urllib.parse.parse_qs(parts[1])
            limit = int(params.get('limit', [20])[0])
            offset = int(params.get('offset', [0])[0])
        
        results = self.analysis_manager.get_analysis_results(analysis_id, limit, offset)
        stats = self.analysis_manager.get_analysis_stats(analysis_id)
        
        response = {
            "analysis_id": analysis_id,
            "results": results,
            "pagination": {
                "limit": limit,
                "offset": offset,
                "total": stats['total_files']
            }
        }
        
        self.send_json_response(response)
    
    def handle_stats_request(self, path: str):
        """Manipula requisição de estatísticas"""
        analysis_id = path.replace('/api/stats/', '')
        
        if not self.analysis_manager:
            self.send_error(500, "Sistema de análise não disponível")
            return
        
        stats = self.analysis_manager.get_analysis_stats(analysis_id)
        self.send_json_response(stats)
    
    def handle_export_request(self, path: str):
        """Manipula requisição de exportação"""
        parts = path.replace('/api/export/', '').split('?')
        analysis_id = parts[0]
        
        if not self.analysis_manager:
            self.send_error(500, "Sistema de análise não disponível")
            return
        
        format = 'json'
        if len(parts) > 1:
            params = urllib.parse.parse_qs(parts[1])
            format = params.get('format', ['json'])[0]
        
        # Simular exportação (implementação completa precisaria do AnalysisManager.export_results)
        results = self.analysis_manager.get_analysis_results(analysis_id, 1000, 0)
        
        if format == 'json':
            content = json.dumps(results, ensure_ascii=False, indent=2, default=str)
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Disposition', f'attachment; filename="analysis_{analysis_id}.json"')
            self.send_header('Content-Length', str(len(content.encode('utf-8'))))
            self.send_cors_headers()
            self.end_headers()
            self.wfile.write(content.encode('utf-8'))
        else:
            self.send_error(501, f"Formato {format} não implementado")
    
    def send_json_response(self, data: Any):
        """Envia resposta JSON"""
        try:
            response = json.dumps(data, ensure_ascii=False, default=str, indent=2)
            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(response.encode('utf-8'))))
            self.send_cors_headers()
            self.end_headers()
            self.wfile.write(response.encode('utf-8'))
        except Exception as e:
            logging.error(f"Erro ao enviar resposta JSON: {e}")
            self.send_error(500, "Erro ao serializar resposta")

class ForensicWebServer:
    """Servidor web principal"""
    
    def __init__(self, host='localhost', port=8000, auth_manager=None, allowed_origins=None):
        self.host = host
        self.port = port
        self.auth_manager = auth_manager
        self.allowed_origins = allowed_origins or []
        self.server = None
    
    def start(self):
        """Inicia o servidor web"""
        try:
            handler = lambda *args, **kwargs: ForensicHTTPRequestHandler(
                *args, 
                auth_manager=self.auth_manager,
                allowed_origins=self.allowed_origins,
                **kwargs
            )
            
            self.server = socketserver.TCPServer((self.host, self.port), handler)
            logging.info(f"Servidor web iniciado em http://{self.host}:{self.port}")
            
            # Executar em thread separada
            server_thread = threading.Thread(target=self.server.serve_forever)
            server_thread.daemon = True
            server_thread.start()
            
            return True
            
        except Exception as e:
            logging.error(f"Erro ao iniciar servidor web: {e}")
            return False
    
    def stop(self):
        """Para o servidor web"""
        if self.server:
            self.server.shutdown()
            logging.info("Servidor web parado")