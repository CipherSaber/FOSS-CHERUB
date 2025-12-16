# FOSS-CHERUB

**Multi-language Vulnerability Scanner with AI-powered Analysis**

FOSS-CHERUB is an advanced security scanning platform that combines static analysis, taint tracking, and AI-powered vulnerability classification to identify security issues across multiple programming languages.

## 🚀 Features

- **Multi-language Support**: Python, JavaScript, Java, C/C++, PHP, Go, Ruby, Rust
- **AI-powered Analysis**: Qwen model for CWE classification and mitigation recommendations
- **Advanced Taint Tracking**: AST-based data flow analysis for precise vulnerability detection
- **Real-time CVE Enrichment**: Integration with NVD database for up-to-date vulnerability information
- **Modern Web Interface**: React-based dashboard with real-time scan monitoring
- **Comprehensive Reporting**: Detailed findings with code snippets and remediation guidance

## 🛠️ Technology Stack

- **Backend**: FastAPI, Python 3.10+
- **Frontend**: Next.js 14, TypeScript, Tailwind CSS
- **AI Model**: Qwen Coder (fine-tuned for security analysis)
- **Static Analysis**: Semgrep with custom taint-mode rules
- **Database**: PostgreSQL with CVE/CWE data
- **Containerization**: Docker support for easy deployment

## 📋 Prerequisites

- Python 3.10 or higher
- Node.js 18 or higher
- Docker (optional, for database)
- Git

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/CipherSaber/FOSS-CHERUB.git
cd FOSS-CHERUB
```

### 2. Install Dependencies

**Backend Dependencies:**
```bash
pip install -r requirements.txt
```

**Frontend Dependencies:**
```bash
cd foss-cherub-ui
npm install
cd ..
```

### 3. Start the Application

```bash
chmod +x start-all.sh
./start-all.sh
```

This will:
- Start PostgreSQL database (if Docker is available)
- Launch the backend API on port 8082
- Start the frontend on port 3002

### 4. Access the Application

- **Web Interface**: http://localhost:3002
- **API Documentation**: http://localhost:8082/docs

## 🔧 Manual Setup

### Backend Setup

```bash
cd backend
python api.py
```

### Frontend Setup

```bash
cd foss-cherub-ui
npm run dev
```

### Database Setup (Optional)

```bash
docker run -d --name foss-cherub-db \
  -e POSTGRES_DB=foss_cherub \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=foss_cherub_2024 \
  -p 5432:5432 \
  postgres:15
```

## 📊 Usage

### Scanning a Repository

1. **Via Web Interface**:
   - Navigate to http://localhost:3002
   - Enter a GitHub repository URL
   - Click "Start Scan"
   - Monitor progress in real-time

2. **Via API**:
   ```bash
   curl -X POST "http://localhost:8082/api/scans" \
     -H "Content-Type: application/json" \
     -d '{"repo_url": "https://github.com/user/repo", "scan_name": "My Scan"}'
   ```

3. **Upload Archive**:
   - Use the web interface to upload ZIP/TAR files
   - Supports compressed source code archives

### Scan Results

Results include:
- **Vulnerability Classification**: CWE mapping with severity levels
- **CVE Information**: Related CVE IDs and CVSS scores
- **Code Context**: Exact file locations and code snippets
- **Taint Analysis**: Data flow tracking for injection vulnerabilities
- **AI Recommendations**: Automated mitigation suggestions

## 🔍 Supported Vulnerability Types

- SQL Injection (CWE-89)
- Cross-Site Scripting (CWE-79)
- Command Injection (CWE-78)
- Code Injection (CWE-95)
- Path Traversal (CWE-22)
- Buffer Overflow (CWE-120)
- Insecure Deserialization (CWE-502)
- And many more...

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │   Backend API   │    │   AI Model      │
│   (Next.js)     │◄──►│   (FastAPI)     │◄──►│   (Qwen)        │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌─────────────────┐    ┌─────────────────┐
                       │   Scanner       │    │   Database      │
                       │   (Semgrep +    │◄──►│   (PostgreSQL)  │
                       │    AST)         │    │                 │
                       └─────────────────┘    └─────────────────┘
```

## 🔧 Configuration

### Environment Variables

```bash
# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_NAME=foss_cherub
DB_USER=postgres
DB_PASSWORD=foss_cherub_2024

# API Configuration
API_PORT=8082
FRONTEND_PORT=3002

# Model Configuration
MODEL_PATH=./data_processing/merged_model
```
##
### Link to the model used
[Qwen Coder 7B](https://huggingface.co/jacpacd/Foss-Cherub-Vuln-Detector)
##

### Custom Rules
Add custom Semgrep rules in `semgrep_taint_rules.yml` for organization-specific vulnerability patterns.

## 📈 Performance

- **Scan Speed**: ~2-5 minutes for typical repositories
- **Memory Usage**: ~4GB RAM (including AI model)
- **Supported File Size**: Up to 100MB archives
- **Concurrent Scans**: Multiple scans supported

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Issues**: [GitHub Issues](https://github.com/CipherSaber/FOSS-CHERUB/issues)
- **Documentation**: [Wiki](https://github.com/CipherSaber/FOSS-CHERUB/wiki)
- **Discussions**: [GitHub Discussions](https://github.com/CipherSaber/FOSS-CHERUB/discussions)

## 🙏 Acknowledgments

- [Semgrep](https://semgrep.dev/) for static analysis engine
- [Qwen](https://github.com/QwenLM/Qwen) for AI model foundation
- [NVD](https://nvd.nist.gov/) for vulnerability database
- [MITRE](https://cwe.mitre.org/) for CWE classification system

---
<img width="1810" height="940" alt="Screenshot from 2025-12-13 19-45-39" src="https://github.com/user-attachments/assets/4a0c8a5b-e263-49bc-b0c3-82396e7ff759" />
<img width="1811" height="938" alt="Screenshot from 2025-12-13 18-39-36" src="https://github.com/user-attachments/assets/0458e013-d71c-40ab-8bdc-0344174f3ff0" />

