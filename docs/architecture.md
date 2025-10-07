ThreatScope Architecture
Overview
ThreatScope is a modern threat intelligence platform built with a microservices-inspired architecture, leveraging advanced data structures and AI for intelligent threat analysis.

System Architecture
┌─────────────────────────────────────────────────────────┐
│                    User Interface                        │
│                                                          │
│  ┌──────────────────┐        ┌──────────────────┐      │
│  │   Dashboard      │        │   API Clients    │      │
│  │  (Streamlit)     │        │   (External)     │      │
│  └────────┬─────────┘        └────────┬─────────┘      │
└───────────┼──────────────────────────┼─────────────────┘
            │                          │
            ▼                          ▼
┌─────────────────────────────────────────────────────────┐
│                    API Layer                             │
│                   (FastAPI)                              │
│                                                          │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐       │
│  │  Analysis  │  │  Threats   │  │   Search   │       │
│  │  Routes    │  │  Routes    │  │   Routes   │       │
│  └────────────┘  └────────────┘  └────────────┘       │
└───────────┬──────────────────────────┬─────────────────┘
            │                          │
            ▼                          ▼
┌─────────────────────────────────────────────────────────┐
│                 Business Logic                           │
│                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │  AI Analyzer │  │ Threat Graph │  │  Collectors  │ │
│  │  (OpenAI)    │  │  (NetworkX)  │  │  (Feeds)     │ │
│  └──────────────┘  └──────────────┘  └──────────────┘ │
│                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │ Bloom Filter │  │ Merkle Tree  │  │ Domain Trie  │ │
│  │(Hash Lookup) │  │(Audit Trail) │  │(Prefix Match)│ │
│  └──────────────┘  └──────────────┘  └──────────────┘ │
└───────────┬──────────────────────────┬─────────────────┘
            │                          │
            ▼                          ▼
┌─────────────────────────────────────────────────────────┐
│                  Data Layer                              │
│                                                          │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐       │
│  │ PostgreSQL │  │   Redis    │  │  File Sys  │       │
│  │(Persistent)│  │  (Cache)   │  │  (Feeds)   │       │
│  └────────────┘  └────────────┘  └────────────┘       │
└─────────────────────────────────────────────────────────┘
Core Components
1. Data Structures Layer
Threat Graph (NetworkX)
Purpose: Model relationships between threats
Implementation: Directed graph using NetworkX
Operations:
Add threats as nodes
Link threats with relationships
Find related threats (BFS/DFS)
Detect campaigns (community detection)
Calculate threat scores (centrality metrics)
Bloom Filter
Purpose: Fast malware hash lookups (O(1))
Implementation: Probabilistic data structure with multiple hash functions
Properties:
Memory-efficient (1M hashes in ~1.5 MB)
No false negatives
Configurable false positive rate (0.1%)
Merkle Tree
Purpose: Tamper-proof audit trail
Implementation: Binary tree with cryptographic hashes
Use Cases:
Compliance logging
Integrity verification
Audit trail for threat analysis
Domain Trie
Purpose: Fast domain/subdomain matching
Implementation: Prefix tree with reverse domain storage
Operations:
Exact domain lookup: O(m) where m = domain length
Prefix search: O(m + k) where k = result count
Wildcard matching support
Priority Queue
Purpose: Alert prioritization
Implementation: Min-heap for efficient priority retrieval
Scoring: Based on threat level and confidence
2. AI Layer
OpenAI Integration
Model: GPT-4 Turbo
Capabilities:
URL analysis (phishing detection)
IP reputation analysis
File hash malware identification
Threat correlation
Natural language search
Report generation
Caching Strategy
Backend: Redis
TTL: 1 hour (configurable)
Purpose: Reduce API costs and improve response time
3. API Layer (FastAPI)
Endpoints
/api/threats - CRUD operations for threats
/api/analyze - AI-powered threat analysis
/api/search - Natural language search
/health - Health check
/stats - Platform statistics
Middleware
Authentication: API key-based
Rate Limiting: 60 requests/minute per client
CORS: Configurable origins
Logging: Request/response logging
Error Handling: Centralized exception handling
4. Threat Intelligence Collectors
Supported Feeds
AbuseIPDB: IP reputation
AlienVault OTX: Multi-source IOCs
URLhaus: Malware URLs
PhishTank: Phishing URLs
Collection Strategy
Scheduled updates (configurable interval)
Automatic retry on failure
Normalization to standard format
Deduplication
5. Dashboard (Streamlit)
Pages
Overview: Real-time metrics and trends
Analysis: AI-powered threat analysis interface
Graph View: Interactive threat relationship visualization
Settings: Configuration management
Features
Real-time updates
Interactive visualizations (Plotly)
Network graph (PyVis)
Export capabilities
Data Flow
Threat Analysis Flow
1. User submits URL/IP/Hash
   ↓
2. API validates input
   ↓
3. Check cache (Redis)
   ├─ Hit → Return cached result
   └─ Miss → Continue
   ↓
4. AI Analyzer (OpenAI)
   ↓
5. Cache result
   ↓
6. Store in database
   ↓
7. Add to threat graph
   ↓
8. Return to user
Feed Collection Flow
1. Scheduled task triggers
   ↓
2. Collector fetches data from feed
   ↓
3. Normalize to standard format
   ↓
4. Deduplicate against existing threats
   ↓
5. Store in database
   ↓
6. Add to threat graph
   ↓
7. Update bloom filter (if hash)
   ↓
8. Update domain trie (if domain)
   ↓
9. Log in merkle tree
Database Schema
Threats Table
sql
- id (UUID, PK)
- threat_type (VARCHAR)
- value (VARCHAR, INDEXED)
- threat_level (VARCHAR, INDEXED)
- confidence (FLOAT)
- first_seen (TIMESTAMP, INDEXED)
- last_seen (TIMESTAMP)
- metadata (JSONB)
- is_active (BOOLEAN, INDEXED)
Threat Relationships Table
sql
- id (UUID, PK)
- source_id (UUID, FK, INDEXED)
- target_id (UUID, FK, INDEXED)
- relation_type (VARCHAR)
- confidence (FLOAT)
- created_at (TIMESTAMP)
Campaigns Table
sql
- id (UUID, PK)
- name (VARCHAR)
- threat_actor (VARCHAR, INDEXED)
- attack_pattern (VARCHAR)
- threat_ids (JSONB)
- is_active (BOOLEAN, INDEXED)
Performance Optimizations
1. Caching Strategy
Redis for AI responses (1 hour TTL)
In-memory cache for frequently accessed data
LRU eviction policy
2. Database Indexing
Composite indexes on (threat_type, threat_level)
Full-text search on threat values
Timestamp-based partitioning (future)
3. Asynchronous Processing
Background feed collection
Async API calls to threat feeds
Non-blocking I/O operations
4. Data Structure Selection
Bloom filter for O(1) hash lookups
Trie for O(m) domain lookups
Graph database for relationship queries
Security Measures
1. Authentication & Authorization
API key authentication
Role-based access control (future)
JWT tokens for dashboard (future)
2. Input Validation
Pydantic models for request validation
URL/IP/hash format validation
SQL injection prevention (ORM)
3. Rate Limiting
Per-client rate limits
Configurable thresholds
DDoS protection
4. Audit Trail
Merkle tree for tamper detection
Complete action logging
Compliance-ready logs
Scalability Considerations
Horizontal Scaling
Stateless API design
Load balancer ready
Shared Redis cache
Database connection pooling
Vertical Scaling
Configurable worker threads
Memory-efficient data structures
Lazy loading strategies
Future Improvements
Message queue (RabbitMQ/Kafka)
Microservices architecture
Container orchestration (Kubernetes)
Read replicas for database
Technology Stack
Language: Python 3.11+
Web Framework: FastAPI
Dashboard: Streamlit
Database: PostgreSQL 14+
Cache: Redis 7+
AI: OpenAI GPT-4
Data Processing: Pandas, NetworkX
Containerization: Docker
CI/CD: GitHub Actions
Deployment Architecture
┌─────────────────────────────────────────┐
│          Load Balancer (Nginx)          │
└───────────────┬─────────────────────────┘
                │
        ┌───────┴────────┐
        │                │
┌───────▼──────┐  ┌──────▼───────┐
│   API (x2)   │  │  Dashboard   │
│   FastAPI    │  │  Streamlit   │
└───────┬──────┘  └──────────────┘
        │
    ┌───┴────┐
    │        │
┌───▼──┐  ┌─▼────┐
│ DB   │  │ Redis│
│ PG   │  │Cache │
└──────┘  └──────┘
Monitoring & Observability
Metrics
API response times
Cache hit rates
Feed collection success rates
Threat detection counts
Logging
Structured logging (JSON)
Log levels: DEBUG, INFO, WARNING, ERROR
Centralized log aggregation (future)
Health Checks
/health endpoint
Database connectivity
Redis connectivity
External feed availability
