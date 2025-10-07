#!/usr/bin/env python3
"""
Setup script para Forensic Tool - Advanced Metadata Analysis
"""

from setuptools import setup, find_packages
from pathlib import Path

# Ler README
readme_path = Path(__file__).parent / "README.md"
long_description = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""

# Ler requirements
requirements_path = Path(__file__).parent / "requirements.txt"
requirements = []
if requirements_path.exists():
    requirements = requirements_path.read_text(encoding="utf-8").strip().split("\n")
    requirements = [req.strip() for req in requirements if req.strip() and not req.startswith("#")]

setup(
    name="forensic-tool",
    version="2.0.0",
    author="Santos (Refatorado)",
    author_email="contato@forensictool.com",
    description="Ferramenta avançada de análise forense de metadados",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Santosxbk/forensic_tool",
    project_urls={
        "Bug Reports": "https://github.com/Santosxbk/forensic_tool/issues",
        "Source": "https://github.com/Santosxbk/forensic_tool",
        "Documentation": "https://github.com/Santosxbk/forensic_tool/docs",
    },
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Legal Industry",
        "Topic :: Security",
        "Topic :: System :: Forensics",
        "Topic :: Utilities",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=22.0.0",
            "flake8>=5.0.0",
            "mypy>=0.991",
            "pre-commit>=2.20.0",
        ],
        "web": [
            "flask>=2.2.0",
            "flask-cors>=4.0.0",
            "gunicorn>=20.1.0",
        ],
        "all": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=22.0.0",
            "flake8>=5.0.0",
            "mypy>=0.991",
            "pre-commit>=2.20.0",
            "flask>=2.2.0",
            "flask-cors>=4.0.0",
            "gunicorn>=20.1.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "forensic-tool=forensic_tool.cli.main:main",
            "forensic-web=forensic_tool.web.server:main",
        ],
    },
    include_package_data=True,
    package_data={
        "forensic_tool": [
            "web/templates/*.html",
            "web/static/css/*.css",
            "web/static/js/*.js",
            "config/*.yaml",
            "config/*.json",
        ],
    },
    zip_safe=False,
    keywords="forensic metadata analysis exif security investigation",
)
