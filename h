ThreatScope/
│
├── .github/
│   └── workflows/
│       ├── ci.yml                    # GitHub Actions (Tests, Linting)
│       └── deploy.yml                # Auto-Deploy (optional)
│
├── docs/
│   ├── architecture.md               # System-Architektur
│   ├── api_documentation.md          # API Docs
│   ├── deployment.md                 # Deployment Guide
│   └── screenshots/                  # Demo-Screenshots
│       ├── dashboard.png
│       ├── threat_graph.png
│       └── analysis.png
│
├── src/
│   ├── __init__.py
│   │
│   ├── core/                         # ⭐ KERN-DATENSTRUKTUREN
│   │   ├── __init__.py
│   │   ├── threat_graph.py           # Graph für Threat Relations
│   │   ├── bloom_filter.py           # Malware Hash Lookups
│   │   ├── merkle_tree.py            # Audit Trail
│   │   ├── domain_trie.py            # Domain Prefix Matching
│   │   └── priority_queue.py         # Alert Priorisierung
│   │
│   ├── ai/                           # 🤖 OPENAI INTEGRATION
│   │   ├── __init__.py
│   │   ├── analyzer.py               # AI Threat Analyzer
│   │   ├── prompts.py                # Prompt Templates
│   │   └── cache.py                  # Response Caching
│   │
│   ├── api/                          # 🌐 REST API
│   │   ├── __init__.py
│   │   ├── main.py                   # FastAPI App
│   │   ├── routes/
│   │   │   ├── __init__.py
│   │   │   ├── threats.py            # /api/threats
│   │   │   ├── analysis.py           # /api/analyze
│   │   │   └── search.py             # /api/search
│   │   ├── models.py                 # Pydantic Models
│   │   ├── dependencies.py           # Shared Dependencies
│   │   └── middleware.py             # Auth, CORS, etc.
│   │
│   ├── collectors/                   # 📡 THREAT INTEL FEEDS
│   │   ├── __init__.py
│   │   ├── base.py                   # Base Collector Class
│   │   ├── abuseipdb.py              # AbuseIPDB Integration
│   │   ├── otx.py                    # AlienVault OTX
│   │   ├── urlhaus.py                # URLhaus (Malware URLs)
│   │   └── phishtank.py              # PhishTank
│   │
│   ├── database/                     # 💾 DATENBANK
│   │   ├── __init__.py
│   │   ├── models.py                 # SQLAlchemy Models
│   │   ├── connection.py             # DB Connection
│   │   └── migrations/               # Alembic Migrations
│   │       └── versions/
│   │
│   ├── dashboard/                    # 📊 STREAMLIT DASHBOARD
│   │   ├── __init__.py
│   │   ├── app.py                    # Main Dashboard
│   │   ├── pages/
│   │   │   ├── 1_threat_overview.py
│   │   │   ├── 2_analysis.py
│   │   │   ├── 3_graph_view.py
│   │   │   └── 4_settings.py
│   │   ├── components/               # Reusable Components
│   │   │   ├── threat_card.py
│   │   │   ├── risk_meter.py
│   │   │   └── graph_visualizer.py
│   │   └── utils/
│   │       ├── charts.py
│   │       └── formatters.py
│   │
│   ├── utils/                        # 🛠️ UTILITIES
│   │   ├── __init__.py
│   │   ├── logging.py                # Custom Logger
│   │   ├── validators.py             # Input Validation
│   │   ├── formatters.py             # Data Formatting
│   │   └── constants.py              # Constants
│   │
│   └── config/                       # ⚙️ CONFIGURATION
│       ├── __init__.py
│       ├── settings.py               # Settings (env vars)
│       └── prompts_templates.py      # AI Prompt Templates
│
├── tests/                            # 🧪 TESTS
│   ├── __init__.py
│   ├── test_graph.py                 # Graph Tests
│   ├── test_bloom_filter.py          # Bloom Filter Tests
│   ├── test_ai_analyzer.py           # AI Tests
│   ├── test_api.py                   # API Tests
│   └── fixtures/                     # Test Data
│       ├── sample_threats.json
│       └── mock_responses.py
│
├── data/                             # 📂 DATA FILES
│   ├── threat_feeds/                 # Downloaded Feeds
│   │   ├── malware_hashes.txt
│   │   ├── malicious_ips.csv
│   │   └── phishing_urls.json
│   ├── cache/                        # Cached Responses
│   └── exports/                      # Exported Reports
│
├── scripts/                          # 🔧 HELPER SCRIPTS
│   ├── setup_db.py                   # Database Setup
│   ├── import_feeds.py               # Import Threat Feeds
│   ├── benchmark.py                  # Performance Tests
│   └── demo_data.py                  # Generate Demo Data
│
├── docker/                           # 🐳 DOCKER
│   ├── Dockerfile                    # Main Dockerfile
│   ├── docker-compose.yml            # Multi-Container Setup
│   └── .dockerignore
│
├── .env.example                      # Environment Variables Template
├── .gitignore                        # Git Ignore
├── requirements.txt                  # Python Dependencies
├── requirements-dev.txt              # Dev Dependencies
├── setup.py                          # Package Setup
├── pyproject.toml                    # Modern Python Config
├── README.md                         # Main Documentation
├── LICENSE                           # MIT License
└── CONTRIBUTING.md                   # Contribution Guide
 
