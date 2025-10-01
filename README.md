🔍 Forensic Tool - Advanced Metadata Analysis

A complete forensic metadata analysis tool with automated web interface.

🌟 Overview

Forensic Tool is a comprehensive Python-based solution for digital forensics and metadata analysis. It provides both a modern web interface and command-line capabilities for efficient file metadata extraction and analysis.
🎯 Use Cases

    Digital Forensics Investigations

    Security Audits

    Incident Response

    Data Analysis

    Educational Purposes

✨ Features
🔍 Metadata Extraction

    Images: EXIF data, camera information, GPS coordinates

    Documents: PDF metadata, Office documents properties

    Audio/Video: Codec information, duration, bitrates

    Archives: Internal structure, file listings

🌐 Web Interface

    Secure directory navigation

    Real-time progress tracking

    Interactive results visualization

    Multiple export formats

    Responsive design

⚡ Performance

    Multi-threaded processing

    SQLite database for large volumes

    Memory-efficient streaming

    Configurable security limits

🔒 Security

    Optional token authentication

    Path traversal protection

    Configurable CORS

    Restricted directory access

    Detailed logging

🤖 Auto-Installation

    Automatic dependency checking

    One-click installation

    Self-healing setup

    No manual configuration needed

⚡ Quick Start
Prerequisites

    Python 3.8 or higher

    pip package manager

Automatic Installation & Usage
bash

# Clone the repository
git clone https://github.com/Santosxbk/forensic_tool.git
cd forensic_tool

# Run directly - dependencies install automatically!
python main.py --gui

That's it! The script will automatically:

    ✅ Check for required dependencies

    ✅ Install missing packages

    ✅ Configure everything automatically

    ✅ Launch the web interface

Manual Installation (Optional)
bash

# Install dependencies manually if preferred
pip install -r requirements.txt

🚀 Usage
Web Interface (Recommended)
bash

# Basic interface (auto-installs dependencies)
python main.py --gui

# Network access
python main.py --gui --host 0.0.0.0 --port 8080

# With authentication
python main.py --gui --auth

# No automatic browser
python main.py --gui --no-browser

Command Line Mode
bash

# Basic analysis
python main.py --cli /path/to/files

# High-performance analysis
python main.py --cli /path/to/files --threads 8 --max-size 2048

# Multiple export formats
python main.py --cli /path/to/files --formato json,csv,excel --output ./reports

🔐 Authentication
Setup Authentication

Environment Variable (Recommended):
bash

export FORENSIC_AUTH_TOKEN="your_super_secret_token_32_chars"
python main.py --gui --auth

Configuration File:
bash

echo "your_super_secret_token" > forensic_tokens.txt
python main.py --gui --auth

Auto-generation:
bash

python main.py --gui --auth
# Token will be generated and displayed in console

📊 Supported Formats
📷 Images

    JPEG/JPG, PNG, BMP, GIF, TIFF, WebP

    EXIF metadata, camera info, GPS data

📄 Documents

    PDF (metadata, encryption, pages)

    Word (.docx, .doc) - author, dates, statistics

    Excel (.xlsx, .xls) - sheets, structure

    PowerPoint (.pptx, .ppt) - slides, layouts

    Text files (.txt, .rtf)

🎵 Media Files

    Audio: MP3, FLAC, WAV, M4A, AAC, OGG

    Video: MP4, AVI, MKV, MOV, WMV

📦 Archives

    ZIP, RAR, 7Z, TAR, GZ

🗂️ Project Structure
text

forensic_tool/
│
├── 📄 main.py                 # Main script with auto-install
├── 🔍 forensic_analyzer.py    # Forensic analysis module
├── 🌐 web_server.py          # Web server and interface
├── 🗄️ database.py            # SQLite database management
├── 🔐 auth_manager.py        # Authentication system
├── 📋 requirements.txt       # Project dependencies
├── 🔧 install_dependencies.py # Standalone installer
│
├── 📊 forensic_results.db    # Database (auto-generated)
├── 📝 forensic_tokens.txt    # Tokens (auto-generated)
└── 📋 forensic_tool.log      # Application logs

🔧 Auto-Installation System
How It Works

    Pre-flight Check - Verifies all required dependencies

    Smart Detection - Identifies missing packages

    Automatic Installation - Installs missing dependencies

    Verification - Confirms successful installation

    Execution - Runs the main application

Supported Packages
Package	Purpose	Auto-Install
pillow	Image analysis & EXIF	✅
pypdf2	PDF metadata	✅
python-docx	Word documents	✅
openpyxl	Excel spreadsheets	✅
python-pptx	PowerPoint files	✅
mutagen	Audio metadata	✅
opencv-python	Video analysis	✅
python-magic	MIME detection	✅
pandas	Data export	✅
tqdm	Progress bars	✅
numpy	Numerical processing	✅
🔌 API Documentation
Endpoints
Endpoint	Method	Description
/api/drives	GET	List available drives
/api/directory/{path}	GET	Browse directory contents
/api/analyze/{path}	GET	Start analysis
/api/status/{id}	GET	Check analysis status
/api/results/{id}	GET	Get analysis results
/api/stats/{id}	GET	Get analysis statistics
/api/export/{id}	GET	Export results
Example API Usage
bash

# Start analysis
curl -X GET "http://localhost:8000/api/analyze//home/user/documents"

# Check status
curl -X GET "http://localhost:8000/api/status/web_1640995200"

# Get results
curl -X GET "http://localhost:8000/api/results/web_1640995200?limit=10&offset=0"

💡 Examples
Example 1: Basic Forensic Analysis
bash

python main.py --cli /home/user/suspicious_files --formato json,csv --output ./forensic_report

Example 2: System Audit
bash

export FORENSIC_AUTH_TOKEN="audit_2024_token"
python main.py --gui --auth --host 0.0.0.0 --port 8080

Example 3: Batch Processing
bash

for dir in /data/disk1 /data/disk2 /data/disk3; do
    python main.py --cli "$dir" --threads 6 --output "/reports/$(basename $dir)"
done

Example 4: Integration with Other Tools
bash

# Generate JSON and process with jq
python main.py --cli /path/analysis --formato json | jq '.[] | select(.Tipo == "PDF")'

🛠️ Troubleshooting
Common Issues

Dependencies not installing:
bash

# The script auto-installs, but if you need manual intervention:
pip install -r requirements.txt

Permission errors:
bash

# Linux/Mac - run with sudo
sudo python main.py --cli /restricted/path

# Or change ownership
sudo chown $USER /restricted/path

Port already in use:
bash

python main.py --gui --port 8081

File too large:
bash

python main.py --cli /path --max-size 2048

Logs and Debugging

Detailed logs are saved in forensic_tool.log:
bash

# Monitor logs in real-time
tail -f forensic_tool.log

# Search for errors
grep -i "error" forensic_tool.log

# Check dependency installation
grep -i "dependencies" forensic_tool.log

Dependency Installation Issues

If auto-installation fails:

    Check Python version:
    bash

python --version
# Should be 3.8 or higher

Manual installation:
bash

pip install pillow pypdf2 python-docx openpyxl python-pptx mutagen opencv-python python-magic pandas tqdm numpy

Use virtual environment:
bash

python -m venv forensic_env
source forensic_env/bin/activate  # Linux/Mac
forensic_env\Scripts\activate    # Windows
pip install -r requirements.txt

🤝 Contributing

We welcome contributions! Please follow these steps:

    Fork the project

    Create a feature branch (git checkout -b feature/AmazingFeature)

    Commit your changes (git commit -m 'Add some AmazingFeature')

    Push to the branch (git push origin feature/AmazingFeature)

    Open a Pull Request

Development Guidelines

    Follow PEP 8 style guide

    Add tests for new features

    Update documentation

    Use semantic commit messages

    Ensure auto-installation works for new dependencies

Adding New Dependencies

When adding new features that require additional packages:

    Update requirements.txt

    Add to the dependencies dictionary in main.py

    Test the auto-installation process

    Update this README

📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
👥 Authors

    Santos - Initial work & auto-installation system - Santosxbk

🙏 Acknowledgments

    Thanks to all contributors who have helped with this project

    Open source libraries that made this tool possible

    Digital forensics community for inspiration and feedback

    Python packaging ecosystem for reliable dependency management


System Service (Linux)
bash

# Create service file
sudo nano /etc/systemd/system/forensic-tool.service

[Unit]
Description=Forensic Tool Web Service
After=network.target

[Service]
Type=simple
User=forensic
WorkingDirectory=/opt/forensic_tool
ExecStart=/usr/bin/python3 main.py --gui --host 0.0.0.0 --port 8000 --auth
Restart=always

[Install]
WantedBy=multi-user.target

# Enable and start service
sudo systemctl enable forensic-tool
sudo systemctl start forensic-tool

🔄 Version
Version 1.0

    ✅ Auto-installation system

    ✅ Modern web interface

    ✅ Enhanced security features

    ✅ Improved performance

    ✅ Better error handling


⭐ If you find this project useful, please give it a star on GitHub!

Last updated: March 2024
Version: 1.0
*Python: 3.8+*
Auto-Install: Enabled
