from datetime import datetime, timezone
from uuid import UUID, uuid4

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.models import Host, Scan, ScanCreateRequest
from app.scanner.discovery import run_discovery
from app.scope import validate_cidr


app = FastAPI(title='RECON API')
app.add_middleware(
    CORSMiddleware,
    allow_origins=['http://localhost:5173'],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)

scans: dict[UUID, Scan] = {}


def discover_scan_hosts(scan_id: UUID, cidr: str) -> None:
    scan = scans[scan_id]
    try:
        discovered_hosts = run_discovery(cidr)
        scan.hosts = [
            Host(ip=host['ip'], hostname=host['hostname'])
            for host in discovered_hosts
        ]
        scan.status = 'completed'
    except Exception as exc:
        scan.status = 'failed'
        scan.error = str(exc)


@app.post('/scans', response_model=Scan, status_code=201)
def create_scan(request: ScanCreateRequest, background_tasks: BackgroundTasks) -> Scan:
    try:
        network = validate_cidr(request.cidr, request.authorized)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    scan = Scan(
        id=uuid4(),
        cidr=str(network),
        status='discovering',
        created_at=datetime.now(timezone.utc),
    )
    scans[scan.id] = scan
    background_tasks.add_task(discover_scan_hosts, scan.id, scan.cidr)
    return scan


@app.get('/scans/{scan_id}', response_model=Scan)
def get_scan(scan_id: UUID) -> Scan:
    scan = scans.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail='Scan not found.')
    return scan