"""
Testes para os módulos utilitários
"""

import pytest
from pathlib import Path
import hashlib

from src.forensic_tool.utils import FileValidator, FileScanner, HashCalculator, HashResult


class TestFileValidator:
    """Testes para a classe FileValidator"""
    
    def test_validate_existing_file(self, sample_files: Path):
        """Testa validação de arquivo existente"""
        validator = FileValidator()
        test_file = sample_files / "test.txt"
        
        is_valid, error = validator.validate_path(test_file)
        assert is_valid
        assert error is None
    
    def test_validate_nonexistent_file(self, temp_dir: Path):
        """Testa validação de arquivo inexistente"""
        validator = FileValidator()
        nonexistent_file = temp_dir / "nonexistent.txt"
        
        is_valid, error = validator.validate_path(nonexistent_file)
        assert not is_valid
        assert "não existe" in error.lower()
    
    def test_validate_file_size_limit(self, temp_dir: Path):
        """Testa validação de limite de tamanho"""
        validator = FileValidator(max_file_size_mb=0.001)  # 1KB limit
        
        # Cria arquivo maior que o limite
        large_file = temp_dir / "large.txt"
        large_file.write_text("x" * 2048)  # 2KB
        
        is_valid, error = validator.validate_path(large_file)
        assert not is_valid
        assert "muito grande" in error.lower()
    
    def test_validate_blocked_extension(self, temp_dir: Path):
        """Testa validação de extensão bloqueada"""
        validator = FileValidator(blocked_extensions={".exe", ".bat"})
        
        blocked_file = temp_dir / "malware.exe"
        blocked_file.write_text("fake executable")
        
        is_valid, error = validator.validate_path(blocked_file)
        assert not is_valid
        assert "bloqueada" in error.lower()
    
    def test_validate_directory(self, sample_files: Path):
        """Testa validação de diretório"""
        validator = FileValidator()
        
        is_valid, error = validator.validate_path(sample_files)
        assert is_valid
        assert error is None
    
    def test_validate_path_depth(self, temp_dir: Path):
        """Testa validação de profundidade de caminho"""
        validator = FileValidator(max_path_depth=2)
        
        # Cria estrutura profunda
        deep_dir = temp_dir / "level1" / "level2" / "level3" / "level4"
        deep_dir.mkdir(parents=True)
        deep_file = deep_dir / "deep.txt"
        deep_file.write_text("deep file")
        
        is_valid, error = validator.validate_path(deep_file)
        assert not is_valid
        assert "profundo" in error.lower()


class TestFileScanner:
    """Testes para a classe FileScanner"""
    
    def test_scan_directory(self, sample_files: Path):
        """Testa escaneamento de diretório"""
        validator = FileValidator()
        scanner = FileScanner(validator, {".txt", ".json", ".csv"})
        
        files = list(scanner.scan_directory(sample_files))
        
        # Deve encontrar pelo menos os arquivos de teste
        file_names = [f.name for f in files]
        assert "test.txt" in file_names
        assert "test.json" in file_names
        assert "test.csv" in file_names
        assert "nested.txt" in file_names  # Do subdiretório
    
    def test_count_files(self, sample_files: Path):
        """Testa contagem de arquivos"""
        validator = FileValidator()
        scanner = FileScanner(validator, {".txt", ".json", ".csv"})
        
        count = scanner.count_files(sample_files)
        assert count >= 4  # Pelo menos os arquivos de teste
    
    def test_scan_with_max_files(self, sample_files: Path):
        """Testa escaneamento com limite máximo"""
        validator = FileValidator()
        scanner = FileScanner(validator, {".txt", ".json", ".csv"})
        
        files = list(scanner.scan_directory(sample_files, max_files=2))
        assert len(files) <= 2
    
    def test_scan_empty_directory(self, temp_dir: Path):
        """Testa escaneamento de diretório vazio"""
        empty_dir = temp_dir / "empty"
        empty_dir.mkdir()
        
        validator = FileValidator()
        scanner = FileScanner(validator, {".txt"})
        
        files = list(scanner.scan_directory(empty_dir))
        assert len(files) == 0
    
    def test_scan_with_extension_filter(self, sample_files: Path):
        """Testa escaneamento com filtro de extensão"""
        validator = FileValidator()
        scanner = FileScanner(validator, {".txt"})  # Apenas .txt
        
        files = list(scanner.scan_directory(sample_files))
        
        for file_path in files:
            assert file_path.suffix == ".txt"


class TestHashCalculator:
    """Testes para a classe HashCalculator"""
    
    def test_calculate_md5(self, sample_files: Path):
        """Testa cálculo de hash MD5"""
        calculator = HashCalculator()
        test_file = sample_files / "test.txt"
        
        result = calculator.calculate_md5(test_file)
        
        assert isinstance(result, HashResult)
        assert result.success
        assert result.hash_value is not None
        assert len(result.hash_value) == 32  # MD5 tem 32 caracteres hex
        assert result.error is None
    
    def test_calculate_sha256(self, sample_files: Path):
        """Testa cálculo de hash SHA256"""
        calculator = HashCalculator()
        test_file = sample_files / "test.txt"
        
        result = calculator.calculate_sha256(test_file)
        
        assert isinstance(result, HashResult)
        assert result.success
        assert result.hash_value is not None
        assert len(result.hash_value) == 64  # SHA256 tem 64 caracteres hex
        assert result.error is None
    
    def test_calculate_multiple_hashes(self, sample_files: Path):
        """Testa cálculo de múltiplos hashes"""
        calculator = HashCalculator()
        test_file = sample_files / "test.txt"
        
        results = calculator.calculate_multiple_hashes(test_file, ["md5", "sha1", "sha256"])
        
        assert len(results) == 3
        assert "md5" in results
        assert "sha1" in results
        assert "sha256" in results
        
        for algo, result in results.items():
            assert isinstance(result, HashResult)
            assert result.success
            assert result.hash_value is not None
    
    def test_hash_consistency(self, sample_files: Path):
        """Testa consistência dos hashes"""
        calculator = HashCalculator()
        test_file = sample_files / "test.txt"
        
        # Calcula o mesmo hash duas vezes
        result1 = calculator.calculate_md5(test_file)
        result2 = calculator.calculate_md5(test_file)
        
        assert result1.hash_value == result2.hash_value
    
    def test_hash_nonexistent_file(self, temp_dir: Path):
        """Testa hash de arquivo inexistente"""
        calculator = HashCalculator()
        nonexistent_file = temp_dir / "nonexistent.txt"
        
        result = calculator.calculate_md5(nonexistent_file)
        
        assert isinstance(result, HashResult)
        assert not result.success
        assert result.hash_value is None
        assert result.error is not None
    
    def test_hash_large_file(self, temp_dir: Path):
        """Testa hash de arquivo grande (teste de chunks)"""
        calculator = HashCalculator(chunk_size=1024)  # 1KB chunks
        
        # Cria arquivo de 5KB
        large_file = temp_dir / "large.txt"
        large_file.write_text("x" * 5120)
        
        result = calculator.calculate_md5(large_file)
        
        assert result.success
        assert result.hash_value is not None
    
    def test_verify_hash_correctness(self, temp_dir: Path):
        """Testa se os hashes calculados estão corretos"""
        calculator = HashCalculator()
        
        # Cria arquivo com conteúdo conhecido
        test_content = "Hello, World!"
        test_file = temp_dir / "known.txt"
        test_file.write_text(test_content, encoding='utf-8')
        
        # Calcula hash com nossa implementação
        result = calculator.calculate_md5(test_file)
        
        # Calcula hash esperado com hashlib diretamente
        expected_hash = hashlib.md5(test_content.encode('utf-8')).hexdigest()
        
        assert result.hash_value == expected_hash
    
    def test_hash_binary_file(self, sample_files: Path):
        """Testa hash de arquivo binário"""
        calculator = HashCalculator()
        binary_file = sample_files / "test.bin"
        
        result = calculator.calculate_sha256(binary_file)
        
        assert result.success
        assert result.hash_value is not None
    
    def test_invalid_algorithm(self, sample_files: Path):
        """Testa algoritmo de hash inválido"""
        calculator = HashCalculator()
        test_file = sample_files / "test.txt"
        
        results = calculator.calculate_multiple_hashes(test_file, ["invalid_algo"])
        
        assert "invalid_algo" in results
        assert not results["invalid_algo"].success
        assert results["invalid_algo"].error is not None


class TestHashResult:
    """Testes para a classe HashResult"""
    
    def test_successful_hash_result(self):
        """Testa criação de resultado bem-sucedido"""
        result = HashResult(
            success=True,
            hash_value="abc123def456",
            algorithm="md5",
            file_path="/test/file.txt",
            duration=0.05
        )
        
        assert result.success
        assert result.hash_value == "abc123def456"
        assert result.algorithm == "md5"
        assert result.file_path == "/test/file.txt"
        assert result.duration == 0.05
        assert result.error is None
    
    def test_failed_hash_result(self):
        """Testa criação de resultado com falha"""
        result = HashResult(
            success=False,
            hash_value=None,
            algorithm="sha256",
            file_path="/test/nonexistent.txt",
            error="File not found"
        )
        
        assert not result.success
        assert result.hash_value is None
        assert result.algorithm == "sha256"
        assert result.error == "File not found"
    
    def test_hash_result_string_representation(self):
        """Testa representação em string do resultado"""
        result = HashResult(
            success=True,
            hash_value="abc123",
            algorithm="md5",
            file_path="/test/file.txt"
        )
        
        str_repr = str(result)
        assert "md5" in str_repr
        assert "abc123" in str_repr
        assert "SUCCESS" in str_repr or "success" in str_repr.lower()
