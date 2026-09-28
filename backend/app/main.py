from datetime import datetime, timezone
from uuid import UUID, uuid4

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.models import Scan, ScanCreateRequest
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


@app.post('/scans', response_model=Scan, status_code=201)
def create_scan(request: ScanCreateRequest) -> Scan:
    try:
        network = validate_cidr(request.cidr, request.authorized)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    scan = Scan(
        id=uuid4(),
        cidr=str(network),
        status='pending',
        created_at=datetime.now(timezone.utc),
    )
    scans[scan.id] = scan
    return scan


@app.get('/scans/{scan_id}', response_model=Scan)
def get_scan(scan_id: UUID) -> Scan:
    scan = scans.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail='Scan not found.')
    return scan