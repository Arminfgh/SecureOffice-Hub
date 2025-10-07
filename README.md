# SecureOffice-Hub
# 🛡️ ThreatScope

**AI-Powered Threat Intelligence Platform with Advanced Data Structures**

ThreatScope is a cutting-edge cybersecurity platform that leverages OpenAI for intelligent threat analysis, combined with sophisticated data structures for ultra-fast threat correlation and detection.

## ✨ Key Features

### 🤖 AI-Powered Analysis
- **Natural Language Queries**: "Show me all Russian APT threats from last week"
- **Intelligent Threat Assessment**: AI explains WHY something is malicious
- **Automated Risk Scoring**: ML-based threat severity calculation

### 📊 Advanced Data Structures
- **Threat Graph**: NetworkX-based relationship mapping between IOCs
- **Bloom Filter**: O(1) malware hash lookups (1M+ hashes)
- **Merkle Tree**: Tamper-proof audit trails for compliance
- **Domain Trie**: Blazing-fast domain prefix matching
- **Priority Queue**: Smart alert prioritization

### 🔍 Real-Time Threat Intelligence
- **AbuseIPDB**: IP reputation scoring
- **AlienVault OTX**: Open Threat Exchange data
- **URLhaus**: Malware distribution URLs
- **PhishTank**: Phishing URL database

### 📈 Interactive Dashboard
- Real-time threat visualization
- Graph-based relationship explorer
- Customizable alerting
- Export capabilities (JSON, CSV, PDF)

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- PostgreSQL 14+
- Redis (optional, for caching)
- OpenAI API key

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/threatscope.git
cd threatscope

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Edit .env with your API keys

# Initialize database
python scripts/setup_db.py

# Import threat feeds
python scripts/import_feeds.py
```

### Run the Application

```bash
# Start API server
uvicorn src.api.main:app --reload

# Start Dashboard (in another terminal)
streamlit run src/dashboard/app.py

# Run with Docker
docker-compose up
```

## 📖 Usage Examples

### Phishing URL Analysis
```python
from src.ai.analyzer import ThreatAnalyzer

analyzer = ThreatAnalyzer()
result = analyzer.analyze_url("paypa1-secure.tk/login")

# Output:
# {
#   "threat_level": "CRITICAL",
#   "confidence": 0.94,
#   "indicators": ["typosquatting", "suspicious_tld", "known_pattern"],
#   "explanation": "This URL impersonates PayPal using lookalike domain..."
# }
```

### Graph-Based Correlation
```python
from src.core.threat_graph import ThreatGraph

graph = ThreatGraph()
graph.add_threat("phishing_url", "http://evil.com")
graph.add_threat("ip_address", "45.76.123.45")
graph.link("phishing_url", "ip_address", "hosts")

# Find all related threats
related = graph.get_related_threats("phishing_url", depth=2)
```

### Natural Language Search
```bash
# Via API
curl -X POST "http://localhost:8000/api/search" \
  -H "Content-Type: application/json" \
  -d '{"query": "Show me all threats from China with CVE references"}'
```

## 🏗️ Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│  Dashboard  │────▶│   FastAPI    │────▶│  Database   │
│ (Streamlit) │     │   Backend    │     │ (Postgres)  │
└─────────────┘     └──────────────┘     └─────────────┘
                            │
                            ▼
                    ┌──────────────┐
                    │  OpenAI API  │
                    └──────────────┘
                            │
                            ▼
                    ┌──────────────────┐
                    │  Threat Feeds    │
                    │ • AbuseIPDB      │
                    │ • OTX            │
                    │ • URLhaus        │
                    └──────────────────┘
```

## 📊 Demo Scenarios

### Scenario 1: Email Phishing Detection
**Problem**: Employee receives suspicious email with link
**Solution**: Analyze URL in 3 seconds → Detect typosquatting → Find 47+ related URLs → Block entire campaign

### Scenario 2: Incident Response
**Problem**: Multiple disconnected security alerts
**Solution**: Graph visualization shows all IOCs are part of ONE coordinated attack

### Scenario 3: Threat Hunting
**Problem**: Finding specific threat patterns across massive datasets
**Solution**: Natural language queries + AI filtering = Instant results

### Scenario 4: Compliance & Auditing
**Problem**: Proving security decisions for audits
**Solution**: Merkle Tree provides tamper-proof logs of all threat analyses

## 🧪 Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src tests/

# Run specific test
pytest tests/test_graph.py -v
```

## 📚 Documentation

- [Architecture Details](docs/architecture.md)
- [API Documentation](docs/api_documentation.md)
- [Deployment Guide](docs/deployment.md)

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md] for details.

## 📄 License

This project is licensed under the MIT License - see [LICENSE] file for details.

## 🙏 Acknowledgments

- OpenAI for GPT-4 API
- Threat intelligence providers (AbuseIPDB, AlienVault, URLhaus, PhishTank)
- Open-source community

## 📧 Contact

- **Author**: Armin Foroughi
- **Email**: arfgh2002@gmail.com

---

**⚡ Made with Python, FastAPI, Streamlit, and OpenAI**
# 🛡️ ThreatScope

**AI-Powered Threat Intelligence Platform with Advanced Data Structures**

ThreatScope is a cutting-edge cybersecurity platform that leverages OpenAI for intelligent threat analysis, combined with sophisticated data structures for ultra-fast threat correlation and detection.

## ✨ Key Features

### 🤖 AI-Powered Analysis
- **Natural Language Queries**: "Show me all Russian APT threats from last week"
- **Intelligent Threat Assessment**: AI explains WHY something is malicious
- **Automated Risk Scoring**: ML-based threat severity calculation

### 📊 Advanced Data Structures
- **Threat Graph**: NetworkX-based relationship mapping between IOCs
- **Bloom Filter**: O(1) malware hash lookups (1M+ hashes)
- **Merkle Tree**: Tamper-proof audit trails for compliance
- **Domain Trie**: Blazing-fast domain prefix matching
- **Priority Queue**: Smart alert prioritization

### 🔍 Real-Time Threat Intelligence
- **AbuseIPDB**: IP reputation scoring
- **AlienVault OTX**: Open Threat Exchange data
- **URLhaus**: Malware distribution URLs
- **PhishTank**: Phishing URL database

### 📈 Interactive Dashboard
- Real-time threat visualization
- Graph-based relationship explorer
- Customizable alerting
- Export capabilities (JSON, CSV, PDF)

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- PostgreSQL 14+
- Redis (optional, for caching)
- OpenAI API key

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/threatscope.git
cd threatscope

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Edit .env with your API keys

# Initialize database
python scripts/setup_db.py

# Import threat feeds
python scripts/import_feeds.py
```

### Run the Application

```bash
# Start API server
uvicorn src.api.main:app --reload

# Start Dashboard (in another terminal)
streamlit run src/dashboard/app.py

# Run with Docker
docker-compose up
```

## 📖 Usage Examples

### Phishing URL Analysis
```python
from src.ai.analyzer import ThreatAnalyzer

analyzer = ThreatAnalyzer()
result = analyzer.analyze_url("paypa1-secure.tk/login")

# Output:
# {
#   "threat_level": "CRITICAL",
#   "confidence": 0.94,
#   "indicators": ["typosquatting", "suspicious_tld", "known_pattern"],
#   "explanation": "This URL impersonates PayPal using lookalike domain..."
# }
```

### Graph-Based Correlation
```python
from src.core.threat_graph import ThreatGraph

graph = ThreatGraph()
graph.add_threat("phishing_url", "http://evil.com")
graph.add_threat("ip_address", "45.76.123.45")
graph.link("phishing_url", "ip_address", "hosts")

# Find all related threats
related = graph.get_related_threats("phishing_url", depth=2)
```

### Natural Language Search
```bash
# Via API
curl -X POST "http://localhost:8000/api/search" \
  -H "Content-Type: application/json" \
  -d '{"query": "Show me all threats from China with CVE references"}'
```

## 🏗️ Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│  Dashboard  │────▶│   FastAPI    │────▶│  Database   │
│ (Streamlit) │     │   Backend    │     │ (Postgres)  │
└─────────────┘     └──────────────┘     └─────────────┘
                            │
                            ▼
                    ┌──────────────┐
                    │  OpenAI API  │
                    └──────────────┘
                            │
                            ▼
                    ┌──────────────────┐
                    │  Threat Feeds    │
                    │ • AbuseIPDB      │
                    │ • OTX            │
                    │ • URLhaus        │
                    └──────────────────┘
```

## 📊 Demo Scenarios

### Scenario 1: Email Phishing Detection
**Problem**: Employee receives suspicious email with link
**Solution**: Analyze URL in 3 seconds → Detect typosquatting → Find 47+ related URLs → Block entire campaign

### Scenario 2: Incident Response
**Problem**: Multiple disconnected security alerts
**Solution**: Graph visualization shows all IOCs are part of ONE coordinated attack

### Scenario 3: Threat Hunting
**Problem**: Finding specific threat patterns across massive datasets
**Solution**: Natural language queries + AI filtering = Instant results

### Scenario 4: Compliance & Auditing
**Problem**: Proving security decisions for audits
**Solution**: Merkle Tree provides tamper-proof logs of all threat analyses

## 🧪 Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src tests/

# Run specific test
pytest tests/test_graph.py -v
```

## 📚 Documentation

- [Architecture Details](docs/architecture.md)
- [API Documentation](docs/api_documentation.md)
- [Deployment Guide](docs/deployment.md)

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## 📄 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- OpenAI for GPT-4 API
- Threat intelligence providers (AbuseIPDB, AlienVault, URLhaus, PhishTank)
- Open-source community

## 📧 Contact

- **Author**: Armin Foroughi
- **Email**: arfgh2002@gmail.com


---

**⚡ Made with Python, FastAPI, Streamlit, and OpenAI**
