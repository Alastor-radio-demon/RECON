# RECON

RECON is a network security dashboard and scanner MVP for authorized internal network reconnaissance. It includes a Python backend for scan orchestration and a React + TypeScript frontend for viewing findings and network risk.

## Project structure

```text
RECON/
├── backend/
│   ├── app/
│   ├── tests/
│   └── ...
├── frontend/
│   ├── src/
│   ├── package.json
│   ├── vite.config.ts
│   └── ...
├── reference/
│   └── recon.html
├── .env.example
├── README.md
└── ...
```

## Stack

- Backend: Python 3.12, FastAPI, Celery, Redis, SQLAlchemy, SQLite, Pydantic v2
- Frontend: React, Vite, TypeScript, CSS (reference faithful port)
- Infrastructure: Docker Compose for API, worker, Redis, and frontend services

## Features

- Validate target CIDR ranges before scanning
- Discover live hosts with network tooling
- Scan ports and services
- Parse Nmap XML output into structured models
- Enrich findings with CVE and exploit metadata
- Score host and network risk
- Show results in a dashboard UI

## Prerequisites

- Python 3.12+
- Node.js 18+
- npm
- Docker and Docker Compose (for containerized runs)
- Optional system tools for later pipeline stages:
  - nmap
  - nuclei
  - sslyze

## Environment setup

Copy the sample environment file:

```bash
cp .env.example .env
```

Update values as needed for your local or lab environment, especially:

- `LAB_MODE`
- `AUTHORIZED`
- `NVD_API_KEY`
- `REDIS_URL`
- `SCAN_CONCURRENCY`

## Backend

From the project root:

```bash
cd backend
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# or .venv\Scripts\activate  # Windows PowerShell
pip install -r requirements.txt
```

If a requirements file is not present yet, install the project dependencies you plan to use for the backend module as they are added.

Run tests:

```bash
python -m unittest backend.tests.test_scope
```

## Frontend

From the project root:

```bash
cd frontend
npm install
npm run dev -- --host 0.0.0.0
```

Then open:

```text
http://localhost:5173/
```

Build for production:

```bash
npm run build
```

## Docker

A compose setup is intended for the app services, including the API, worker, Redis, and frontend containers. The project expects these to be configured in a later iteration of the deployment layer.

## Security notes

- Never scan networks unless you own them or have explicit authorization.
- Private ranges are restricted unless `LAB_MODE=true`.
- Tool output must be sanitized before it reaches the UI.
- Secrets must remain in environment variables and never be committed to source control.

## License

This project is for internal use and is not distributed as a public product.
