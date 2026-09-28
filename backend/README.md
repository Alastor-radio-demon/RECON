# RECON Backend

FastAPI API for validating authorized scan scopes and storing pending scans in memory. This MVP does not run Nmap.

## Setup

From the `backend/` directory, create and activate a Python 3.12 virtual environment, then install dependencies:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Set `LAB_MODE` and `MAX_PREFIX` in `.env` as needed. `LAB_MODE` defaults to `true`; private ranges are rejected when it is `false`. `MAX_PREFIX=24` permits networks of `/24` or smaller.

## Run

```powershell
uvicorn app.main:app --reload --port 8000
```

The API documentation is available at `http://localhost:8000/docs`.

## Endpoints

- `POST /scans` accepts `{"cidr":"192.168.1.0/24","authorized":true}` and returns a pending scan. Invalid or unauthorized scopes return HTTP 400.
- `GET /scans/{id}` returns a stored scan or HTTP 404. Scans are held in memory and are cleared when the process restarts.

## Tests

```powershell
python -m pytest
```