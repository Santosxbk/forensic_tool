# 🔍 Forensic Tool - Advanced Metadata Analysis

![Python](https://img.shields.io/badge/Python-3.8%252B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Version](https://img.shields.io/badge/Version-2.0-orange)
![Auto Install](https://img.shields.io/badge/Auto_Install-Enabled-brightgreen)

A complete Python-based forensic metadata analysis tool with **web interface** and **CLI support**.

---

## 🌟 Features

<details>
<summary>Metadata Extraction</summary>

* **Images:** EXIF, camera info, GPS
* **Documents:** PDF, Word, Excel, PowerPoint, Text
* **Audio/Video:** Codec info, duration, bitrate
* **Archives:** ZIP, RAR, 7Z, TAR, GZ

</details>

<details>
<summary>Web Interface</summary>

* Secure navigation
* Real-time progress
* Interactive visualization
* Multi-format export
* Responsive design

</details>

<details>
<summary>Performance & Security</summary>

* Multi-threaded processing
* SQLite database
* Memory-efficient streaming
* Token authentication (optional)
* Path traversal protection

</details>

<details>
<summary>Auto-Installation</summary>

* One-click setup
* Auto dependency check & install
* Self-healing configuration

</details>

---

## 🚀 Quick Start

### Automatic Installation

```bash
git clone https://github.com/Santosxbk/forensic_tool.git
cd forensic_tool
python main.py --gui
```

### Manual Installation (Optional)

```bash
pip install -r requirements.txt
```

---

## 🖥 Usage

### Web Interface (Recommended)

```bash
python main.py --gui
python main.py --gui --host 0.0.0.0 --port 8080
python main.py --gui --auth
python main.py --gui --no-browser
```

### CLI Mode

```bash
python main.py --cli /path/to/files
python main.py --cli /path/to/files --threads 8 --max-size 2048
python main.py --cli /path/to/files --formato json,csv,excel --output ./reports
```

---

## 🔐 Authentication

```bash
# Environment variable
export FORENSIC_AUTH_TOKEN="your_super_secret_token_32_chars"

# Configuration file
echo "your_super_secret_token" > forensic_tokens.txt

# Auto-generation
python main.py --gui --auth
```

---

## 📂 Supported Formats

| Type      | Formats                                     |
| --------- | ------------------------------------------- |
| Images    | JPEG, PNG, BMP, GIF, TIFF, WebP             |
| Documents | PDF, DOCX/DOC, XLSX/XLS, PPTX/PPT, TXT, RTF |
| Audio     | MP3, FLAC, WAV, M4A, AAC, OGG               |
| Video     | MP4, AVI, MKV, MOV, WMV                     |
| Archives  | ZIP, RAR, 7Z, TAR, GZ                       |

---

## 🔌 API Examples

```bash
curl -X GET "http://localhost:8000/api/analyze//home/user/documents"
curl -X GET "http://localhost:8000/api/status/web_1640995200"
curl -X GET "http://localhost:8000/api/results/web_1640995200?limit=10&offset=0"
```

---

## 💡 Quick Examples

* **Basic Analysis**

```bash
python main.py --cli /home/user/suspicious_files --formato json,csv --output ./report
```

* **System Audit**

```bash
export FORENSIC_AUTH_TOKEN="audit_2024_token"
python main.py --gui --auth --host 0.0.0.0 --port 8080
```

* **Batch Processing**

```bash
for dir in /data/disk1 /data/disk2; do
  python main.py --cli "$dir" --threads 6 --output "/reports/$(basename $dir)"
done
```

* **Integration with Other Tools**

```bash
python main.py --cli /path/analysis --formato json | jq '.[] | select(.Tipo == "PDF")'
```

---

## 🛠 Troubleshooting

* **Dependencies:** `pip install -r requirements.txt`
* **Permission errors:** `sudo python main.py ...` or `sudo chown $USER /path`
* **Port in use:** `python main.py --gui --port 8081`
* **File too large:** `--max-size 2048`
* **Logs:** `tail -f forensic_tool.log`

---

## 🤝 Contributing

1. Fork the repo
2. Create a branch: `git checkout -b feature/AmazingFeature`
3. Commit: `git commit -m 'Add feature'`
4. Push: `git push origin feature/AmazingFeature`
5. Open a Pull Request

---

## 👥 Authors

**Santos** - Initial work & auto-installation system - [Santosxbk](https://github.com/Santosxbk)

---

⭐ If this tool helps you, give it a star on GitHub!
