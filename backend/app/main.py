import asyncio
import logging
from datetime import datetime, timezone
from uuid import UUID, uuid4

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.models import CVE, Host, Port, Scan, ScanCreateRequest, ScanSummary, VulnScriptFinding
from app.scanner.discovery import run_discovery
from app.scanner.enrich import lookup_cves
from app.scanner.portscan import run_portscan
from app.scanner.scoring import score_host, score_network
from app.scanner.vulnscan import run_vulnscan
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
portscan_semaphore = asyncio.Semaphore(5)
logger = logging.getLogger(__name__)


async def scan_host(host: Host) -> None:
    async with portscan_semaphore:
        host.status = 'scanning'
        try:
            try:
                result = await asyncio.to_thread(run_portscan, host.ip)
                host.ports = [Port(**port) for port in result['ports']]
            except Exception:
                logger.exception('Port scan failed for host %s', host.ip)

            host.score, host.grade, host.risk_reasons = score_host(host)
            for port in host.ports:
                if port.product and port.version:
                    port.cves = [CVE(**cve) for cve in await lookup_cves(port.product, port.version)]

            try:
                findings = await asyncio.to_thread(run_vulnscan, host.ip)
                host.vuln_findings = [VulnScriptFinding(**finding) for finding in findings]
            except Exception:
                logger.exception('Nmap vulnerability scan failed for host %s', host.ip)
        finally:
            host.status = 'done'


async def discover_scan_hosts(scan_id: UUID, cidr: str) -> None:
    scan = scans[scan_id]
    try:
        discovered_hosts = await asyncio.to_thread(run_discovery, cidr)
        scan.hosts = [
            Host(ip=host['ip'], hostname=host['hostname'])
            for host in discovered_hosts
        ]
        await asyncio.gather(*(scan_host(host) for host in scan.hosts))
        scan.network_score, scan.network_grade = score_network(scan.hosts)
        if any(host.status != 'done' for host in scan.hosts):
            raise RuntimeError('Scan host tasks completed without finishing every host.')
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


@app.get('/scans', response_model=list[ScanSummary])
def list_scans() -> list[ScanSummary]:
    return [
        ScanSummary(
            id=scan.id,
            cidr=scan.cidr,
            status=scan.status,
            created_at=scan.created_at,
            network_score=scan.network_score,
            network_grade=scan.network_grade,
            host_count=len(scan.hosts),
        )
        for scan in sorted(scans.values(), key=lambda item: item.created_at, reverse=True)
    ]


@app.get('/scans/{scan_id}', response_model=Scan)
def get_scan(scan_id: UUID) -> Scan:
    scan = scans.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail='Scan not found.')
    return scan