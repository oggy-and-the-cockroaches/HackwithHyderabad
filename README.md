# 🚢 Shipcheck — AI Pre-Ship Auditor with Hindsight Memory

**Shipcheck** is an enterprise-grade, AI-powered pre-shipment code auditor and repository health assessment platform. Designed to sit between local development and production deployment, Shipcheck scans software projects for security vulnerabilities, privacy compliance leaks, production readiness risks, and reliability flaws — preserving historical context and issue memory across successive scans using its proprietary **Hindsight Engine**.

---

## 🌟 Key Features

* **🛡️ Security Audit**: Detects hardcoded secrets, API keys, unescaped `eval()` execution, SQL injection risks, insecure cryptographic primitives, and permissive CORS setups.
* **🔒 Privacy & Compliance Audit**: Identifies unencrypted PII storage, logging of sensitive user data, unauthorized telemetry tracking, and missing privacy consent mechanisms.
* **🚀 Production Readiness**: Flags remaining `DEBUG=True` flags, leftover `console.log()` / print statements, hardcoded `localhost` URLs, and unhandled exception blocks.
* **⚡ Reliability & Robustness**: Detects missing network timeouts, unhandled promise rejections, unclosed file/database resource handles, and missing circuit breakers.
* **🧠 Hindsight Memory Engine**: Tracks historical scans per project to distinguish between **New**, **Unresolved**, **Fixed**, and **Reintroduced** issues across codebase iterations.
* **🤖 AI-Powered Remediation**: Generates detailed explanations, priority orderings, and exact code fix recommendations powered by LLM integration.
* **📊 Modern Glassmorphism Dashboard**: Responsive Single-Page Application (SPA) frontend providing real-time scan progress visualization, category filters, and downloadable JSON audit reports.
* **📦 Standalone Executable**: Single `.exe` file with bundled frontend and backend — no Python installation required on target machines.

---

## 🏗️ System Architecture

```mermaid
graph TD
    Developer((Developer)) -->|uses| Dashboard[Dashboard SPA<br>[app.js]]
    Dashboard -->|HTTP requests| FastAPI[FastAPI App<br>[main.py]]
    FastAPI -->|retrieves reports| Dashboard
    
    subgraph Application API
        FastAPI -->|mounts router| ProjectAPI[Project API<br>[projects.py]]
        FastAPI -->|mounts router| ScanAPI[Scan API<br>[scans.py]]
        FastAPI -->|mounts router| ReportsAPI[Reports API<br>[reports.py]]
        FastAPI -->|mounts router| HindsightAPI[Hindsight API<br>[hindsight.py]]
    end
    
    subgraph Audit Pipeline
        ProjectAPI -->|stores uploads| UploadedProjects[(Uploaded Projects<br>[schema.py])]
        ProjectAPI -->|detects context| ProjectDetector[Project Detector]
        ProjectDetector -->|inspects project| UploadedProjects
        
        ScanAPI -->|runs scan| ScanOrchestrator[Scan Orchestrator<br>[scanner.py]]
        
        ScanOrchestrator -->|scans files| SecurityChecks[Security Checks<br>[security.py]]
        ScanOrchestrator -->|dispatches| PrivacyChecks[Privacy Checks<br>[privacy.py]]
        ScanOrchestrator -->|dispatches| ProductionChecks[Production Checks<br>[production.py]]
        ScanOrchestrator -->|dispatches| ReliabilityChecks[Reliability Checks<br>[reliability.py]]
        ScanOrchestrator -->|requests remediation| AIRemediation[AI Remediation<br>[llm.py]]
        
        SecurityChecks -->|creates findings| FindingModel[Finding Model<br>[base.py]]
        PrivacyChecks -->|creates findings| FindingModel
        ProductionChecks -->|creates findings| FindingModel
        ReliabilityChecks -->|creates findings| FindingModel
        AIRemediation -->|creates findings| FindingModel
    end
    
    subgraph Reports And Memory
        ScanAPI -->|records scan| SQLiteStore[(SQLite Store<br>[schema.py])]
        ReportsAPI -->|reads and updates| SQLiteStore
        HindsightAPI -->|persists and compares| SQLiteStore
        HindsightAPI -->|records memory| HindsightService[Hindsight Service<br>[hindsight.py]]
        HindsightService -->|stores history| SQLiteStore
    end
    
    AIRemediation -.->|generates analysis| GrokAPI[Grok API]
    AIRemediation -.->|generates analysis| GeminiAPI[Gemini API]
    HindsightService -.->|retains scan context| GeminiAPI
```

---

## 📁 Repository Structure

```
Shipcheck/
├── backend/
│   ├── api/                   # REST API Routers
│   │   ├── projects.py        # Project creation, listing, zip upload
│   │   ├── scans.py           # Scan triggering, background status polling
│   │   └── reports.py         # Audit report retrieval, findings update, export
│   ├── database/
│   │   └── schema.py          # SQLite connection manager & schema creation
│   ├── models/
│   │   └── schemas.py         # Pydantic data schemas & enums
│   ├── scanners/              # Static analysis & rule engine scanners
│   │   ├── base.py            # Base Scanner class & Finding data model
│   │   ├── security.py        # Secrets, injections, unsafe evals, CORS checks
│   │   ├── privacy.py         # PII detection, unencrypted storage, telemetry
│   │   ├── production.py      # Debug flags, print statements, localhost URLs
│   │   └── reliability.py     # Missing timeouts, unhandled errors, resource leaks
│   ├── services/              # Core business services
│   │   ├── scanner.py         # Multi-scanner orchestrator & AST engine
│   │   ├── hindsight.py       # Historical scan comparison & memory manager
│   │   ├── llm.py             # LLM reasoning & automated fix generator
│   │   └── project_detector.py# Auto-detection of languages, frameworks & tech stack
│   ├── projects/              # File storage directory for uploaded projects
│   ├── main.py                # FastAPI entry point & app configuration
│   └── shipcheck.db           # SQLite database store
├── frontend/
│   ├── index.html             # Dashboard markup & SPA layout
│   ├── app.js                 # Frontend application logic & API client
│   └── styles.css             # Glassmorphism dark-mode CSS design system
├── dist/
│   └── Shipcheck.exe          # Standalone Windows executable (built artifact)
├── .env.example               # Environment variables configuration guide
└── README.md                  # Detailed project documentation
```

---

## 🗄️ Database Schema & Hindsight Engine

Shipcheck uses an SQLite database (`shipcheck.db`) configured with foreign key enforcement and row-factory mapping.

### Tables

1. **`projects`**:
   - `id` (TEXT, PK): Unique UUID v4.
   - `name` (TEXT): Name of the project.
   - `created_at` (TIMESTAMP): Project creation timestamp.
   - `last_scan_at` (TIMESTAMP): Timestamp of the latest completed audit.
   - `project_context` (TEXT JSON): Detected languages, frameworks, entry points, and deployment configurations.

2. **`scans`**:
   - `id` (TEXT, PK): Unique scan run ID.
   - `project_id` (TEXT, FK): Foreign key referencing `projects(id)`.
   - `status` (TEXT): Scan lifecycle status (`queued`, `running`, `completed`, `failed`).
   - `summary` (TEXT JSON): Aggregated counters grouped by severity and category.

3. **`findings`**:
   - `id` (TEXT, PK): Persistent finding UUID across scans.
   - `scan_id` (TEXT, FK): Foreign key referencing `scans(id)`.
   - `category` (TEXT): Category (`security`, `privacy`, `reliability`, `production`).
   - `severity` (TEXT): Severity level (`critical`, `high`, `medium`, `low`, `info`).
   - `title` / `description` / `evidence` (TEXT): Finding title, full description, and offending code snippet.
   - `file_path` / `line_number` (TEXT/INT): Location of issue within the project.
   - `status` (TEXT): State (`open`, `fixed`, `acknowledged`).
   - `first_detected_scan` / `last_detected_scan` (TEXT): Foreign keys tracking the issue's lifecycle.

4. **`hindsight_memory`**:
   - `id` (INTEGER, PK AUTO): Developer decision log ID.
   - `project_id` (TEXT, FK): Target project.
   - `finding_id` (TEXT, FK): Associated finding.
   - `type` (TEXT): Note type (`note`, `exception`, `decision`).
   - `content` (TEXT): Notes recorded by developers.

---

## ⚙️ Audit Scanners

Shipcheck's scanning engine ([`backend/services/scanner.py`](file:///c:/Users/Ajay/Desktop/Shipcheck/backend/services/scanner.py)) parses project files using AST analysis for Python and regular expression pattern matching across multiple file types (`.py`, `.js`, `.ts`, `.json`, `.env`, `.yaml`).

| Scanner Category | Focus Area | Checks & Patterns |
| :--- | :--- | :--- |
| **Security** | Vulnerabilities & Exploits | Hardcoded AWS/Stripe keys, RSA private keys, `eval()`, `exec()`, raw SQL string formatting, weak hash functions (MD5/SHA1), wildcard CORS (`*`). |
| **Privacy** | Data Leakage & Compliance | Plaintext storage of SSNs, emails, credit cards, logging sensitive request payloads, unencrypted PII in databases, missing telemetry opt-out. |
| **Production Readiness** | Launch Preparedness | `DEBUG = True` in production configs, `console.log()`/`print()` statements, hardcoded `http://localhost`, missing environment variable fallbacks. |
| **Reliability** | Exception & Resource Leakage | HTTP requests without explicit timeouts, unhandled async promise rejections, unclosed file descriptors, empty `except:` pass blocks. |

---

## 🔌 API Reference

### Projects API
* `GET /api/projects`: List all registered projects.
* `POST /api/projects`: Register a new project.
* `POST /api/projects/{id}/upload`: Upload project code archive (`.zip`).

### Scans API
* `POST /api/scans`: Trigger a new background audit scan.
* `GET /api/scans/{id}/status`: Poll real-time progress (`progress` percentage, step `message`, `status`).
* `GET /api/scans/project/{project_id}`: List all past scans for a project.

### Reports & Findings API
* `GET /api/reports/scan/{scan_id}`: Fetch complete audit report and findings.
* `GET /api/reports/scan/{scan_id}/comparison`: Compare current scan against historical scans via Hindsight.
* `POST /api/reports/findings/{finding_id}/status`: Update finding status (`open`, `fixed`, `acknowledged`).

---

## 💻 Getting Started

### Prerequisites
* Python 3.9+ installed
* Virtual environment (`venv`)

### Installation & Execution (Development Mode)

1. **Activate the Virtual Environment**:
   ```powershell
   # Windows PowerShell
   .\venv\Scripts\Activate.ps1
   ```

2. **Configure Environment Variables** (Optional):
   Copy `.env.example` to `.env` if custom configurations or LLM API keys are desired:
   ```bash
   cp .env.example .env
   ```

3. **Run the Backend & Web Dashboard**:
   ```bash
   python backend/main.py
   ```

4. **Access Shipcheck**:
   Open your browser and navigate to:
   ```
   http://127.0.0.1:8000
   ```

---

## 📦 Building & Running Standalone Executable (Windows)

Shipcheck can be packaged as a single `.exe` file that includes both the FastAPI backend and the SPA frontend — no Python installation required on the target machine.

### Building the Executable

```powershell
# Activate virtual environment
.\venv\Scripts\Activate.ps1

# Install PyInstaller
pip install pyinstaller

# Build the executable
python -m pyinstaller Shipcheck.spec --clean
```

The executable will be created at `dist/Shipcheck.exe`.

### Running the Executable

```powershell
# Navigate to dist folder
cd dist

# Run Shipcheck
.\Shipcheck.exe
```

The server starts at **http://127.0.0.1:8001** with:
- **Frontend Dashboard**: `http://127.0.0.1:8001/`
- **API Endpoints**: `http://127.0.0.1:8001/api/*`
- **Health Check**: `http://127.0.0.1:8001/api/health`

### Notes
- The executable creates its own `projects/` directory and `shipcheck.db` SQLite database in the same folder as the `.exe`
- LLM features (AI remediation) require `GEMINI_API_KEY` or `GROK_API_KEY` in `.env` file alongside the executable
- Port 8001 is used by default to avoid conflicts with development servers on 8000

---

## 🤝 Contributing & Extension

* **Adding New Scanners**: Inherit from `BaseScanner` in [`backend/scanners/base.py`](file:///c:/Users/Ajay/Desktop/Shipcheck/backend/scanners/base.py) and register your scanner class in `ScannerService`.
* **Custom Rules**: Add AST nodes or regular expression checks to respective category files inside [`backend/scanners/`](file:///c:/Users/Ajay/Desktop/Shipcheck/backend/scanners).

---
*Developed with FastAPI, Python, Vanilla JS, and Hindsight Memory Engine.*
