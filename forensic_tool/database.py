"""
MÓDULO DE BANCO DE DADOS
Gerencia resultados em SQLite para evitar estouro de memória
"""

import sqlite3
import json
import threading
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional

class ResultsDatabase:
    """Gerencia resultados em SQLite"""
    
    def __init__(self, db_path: str = "forensic_results.db"):
        self.db_path = Path(db_path)
        self._lock = threading.Lock()
        self._init_db()
    
    def _init_db(self):
        """Inicializa o banco de dados"""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Tabela de análises
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS analyses (
                    analysis_id TEXT PRIMARY KEY,
                    directory_path TEXT,
                    total_files INTEGER,
                    processed_files INTEGER,
                    start_time TEXT,
                    end_time TEXT,
                    status TEXT,
                    error_message TEXT
                )
            ''')
            
            # Tabela de resultados
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    analysis_id TEXT,
                    file_name TEXT,
                    file_path TEXT,
                    file_size INTEGER,
                    file_extension TEXT,
                    file_type TEXT,
                    analysis_data TEXT,
                    analysis_success BOOLEAN,
                    timestamp TEXT,
                    FOREIGN KEY (analysis_id) REFERENCES analyses (analysis_id)
                )
            ''')
            
            # Índices para performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_analysis_id ON results(analysis_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_file_type ON results(file_type)')
            
            conn.commit()
            conn.close()
    
    def save_analysis_metadata(self, analysis_id: str, directory_path: str, total_files: int):
        """Salva metadados da análise"""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO analyses 
                (analysis_id, directory_path, total_files, processed_files, start_time, status)
                VALUES (?, ?, ?, 0, ?, 'running')
            ''', (analysis_id, directory_path, total_files, datetime.now().isoformat()))
            
            conn.commit()
            conn.close()
    
    def save_result(self, analysis_id: str, result: Dict[str, Any]):
        """Salva um resultado individual"""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Extrair campos principais para indexação
            file_name = result.get('Nome_Arquivo', '')
            file_path = result.get('Caminho_Absoluto', '')
            file_size = result.get('Tamanho_Bytes', 0)
            file_extension = result.get('Extensao', '')
            file_type = result.get('Tipo', 'Desconhecido')
            analysis_success = result.get('Analise_Concluida', False)
            
            cursor.execute('''
                INSERT INTO results 
                (analysis_id, file_name, file_path, file_size, file_extension, 
                 file_type, analysis_data, analysis_success, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                analysis_id,
                file_name,
                file_path,
                file_size,
                file_extension,
                file_type,
                json.dumps(result, ensure_ascii=False, default=str),
                analysis_success,
                datetime.now().isoformat()
            ))
            
            # Atualizar contador de progresso
            cursor.execute('''
                UPDATE analyses 
                SET processed_files = (
                    SELECT COUNT(*) FROM results WHERE analysis_id = ?
                )
                WHERE analysis_id = ?
            ''', (analysis_id, analysis_id))
            
            conn.commit()
            conn.close()
    
    def update_analysis_status(self, analysis_id: str, status: str, error_message: str = None):
        """Atualiza status da análise"""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            if status == 'completed':
                cursor.execute('''
                    UPDATE analyses 
                    SET status = ?, end_time = ?, error_message = ?
                    WHERE analysis_id = ?
                ''', (status, datetime.now().isoformat(), error_message, analysis_id))
            else:
                cursor.execute('''
                    UPDATE analyses 
                    SET status = ?, error_message = ?
                    WHERE analysis_id = ?
                ''', (status, error_message, analysis_id))
            
            conn.commit()
            conn.close()
    
    def get_analysis_status(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        """Obtém status da análise"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT analysis_id, directory_path, total_files, processed_files, 
                   start_time, end_time, status, error_message
            FROM analyses 
            WHERE analysis_id = ?
        ''', (analysis_id,))
        
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return {
                'analysis_id': row[0],
                'directory': row[1],
                'total_files': row[2],
                'processed_files': row[3],
                'start_time': row[4],
                'end_time': row[5],
                'status': row[6],
                'error': row[7]
            }
        return None
    
    def get_analysis_results(self, analysis_id: str, limit: int = 1000, offset: int = 0) -> List[Dict[str, Any]]:
        """Obtém resultados da análise com paginação"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT analysis_data 
            FROM results 
            WHERE analysis_id = ? 
            ORDER BY id 
            LIMIT ? OFFSET ?
        ''', (analysis_id, limit, offset))
        
        results = []
        for row in cursor.fetchall():
            try:
                results.append(json.loads(row[0]))
            except json.JSONDecodeError:
                continue
        
        conn.close()
        return results
    
    def get_analysis_stats(self, analysis_id: str) -> Dict[str, Any]:
        """Obtém estatísticas da análise"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Total de arquivos por tipo
        cursor.execute('''
            SELECT file_type, COUNT(*) 
            FROM results 
            WHERE analysis_id = ? 
            GROUP BY file_type
        ''', (analysis_id,))
        
        type_dist = {row[0]: row[1] for row in cursor.fetchall()}
        
        # Estatísticas de sucesso
        cursor.execute('''
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN analysis_success = 1 THEN 1 ELSE 0 END) as successful,
                SUM(CASE WHEN analysis_success = 0 THEN 1 ELSE 0 END) as failed
            FROM results 
            WHERE analysis_id = ?
        ''', (analysis_id,))
        
        stats_row = cursor.fetchone()
        conn.close()
        
        return {
            'total_files': stats_row[0] if stats_row else 0,
            'successful': stats_row[1] if stats_row else 0,
            'failed': stats_row[2] if stats_row else 0,
            'type_distribution': type_dist
        }
    
    def cleanup_old_analyses(self, days_old: int = 30):
        """Limpa análises antigas"""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cutoff_date = datetime.now().timestamp() - (days_old * 24 * 60 * 60)
            cutoff_iso = datetime.fromtimestamp(cutoff_date).isoformat()
            
            # Encontrar análises antigas
            cursor.execute('''
                SELECT analysis_id FROM analyses 
                WHERE start_time < ?
            ''', (cutoff_iso,))
            
            old_analyses = [row[0] for row in cursor.fetchall()]
            
            # Deletar resultados das análises antigas
            for analysis_id in old_analyses:
                cursor.execute('DELETE FROM results WHERE analysis_id = ?', (analysis_id,))
            
            # Deletar análises antigas
            cursor.execute('DELETE FROM analyses WHERE start_time < ?', (cutoff_iso,))
            
            conn.commit()
            conn.close()
            
            return len(old_analyses)