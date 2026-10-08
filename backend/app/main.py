import asyncio
import logging
from datetime import datetime, timezone
from uuid import UUID, uuid4

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.responses import Response
from fastapi.middleware.cors import CORSMiddleware

from app.models import CVE, Host, Port, Scan, ScanCreateRequest, ScanSummary, VulnScriptFinding, WebFinding
from app.reporting.pdf_report import build_report
from app.scanner.advisor import get_recommendations
from app.scanner.discovery import run_discovery
from app.scanner.enrich import lookup_cves
from app.scanner.portscan import run_portscan
from app.scanner.scoring import score_host, score_network
from app.scanner.vulnscan import run_vulnscan
from app.scanner.webscan import run_nuclei
from app.scope import classify_target, validate_cidr


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


async def scan_host(host: Host, depth: str = 'full') -> None:
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

            target_urls = []
            for port in host.ports:
                service = port.service.lower()
                product = (port.product or '').lower()
                if service not in ('http', 'https', 'http-proxy') and not any(
                    marker in product for marker in ('apache', 'nginx', 'http')
                ):
                    continue

                scheme = 'https' if port.port in (443, 8443) else 'http'
                target_urls.append(f'{scheme}://{host.ip}:{port.port}')

            if depth == 'full':
                scan_results = await asyncio.gather(
                    asyncio.to_thread(run_vulnscan, host.ip),
                    *(asyncio.to_thread(run_nuclei, target_url) for target_url in target_urls),
                    return_exceptions=True,
                )
                vuln_result = scan_results[0]
                if isinstance(vuln_result, Exception):
                    logger.error('Nmap vulnerability scan failed for host %s: %s', host.ip, vuln_result)
                else:
                    try:
                        host.vuln_findings = [VulnScriptFinding(**finding) for finding in vuln_result]
                    except Exception:
                        logger.exception('Nmap vulnerability scan returned invalid findings for host %s', host.ip)

                for target_url, nuclei_result in zip(target_urls, scan_results[1:]):
                    if isinstance(nuclei_result, Exception):
                        logger.error('Nuclei web scan failed for %s: %s', target_url, nuclei_result)
                        continue
                    try:
                        host.web_findings.extend(WebFinding(**finding) for finding in nuclei_result)
                    except Exception:
                        logger.exception('Nuclei web scan returned invalid findings for %s', target_url)

                host.ai_recommendations = await get_recommendations(host)
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
        await asyncio.gather(*(scan_host(host, scan.depth) for host in scan.hosts))
        scan.network_score, scan.network_grade = score_network(scan.hosts)
        if any(host.status != 'done' for host in scan.hosts):
            raise RuntimeError('Scan host tasks completed without finishing every host.')
        scan.status = 'completed'
    except Exception as exc:
        scan.status = 'failed'
        scan.error = str(exc)


async def scan_single_host(scan_id: UUID, ip: str) -> None:
    scan = scans[scan_id]
    try:
        scan.hosts = [Host(ip=ip)]
        await scan_host(scan.hosts[0], scan.depth)
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
        target = classify_target(request.cidr)
        if target['type'] == 'cidr':
            network = validate_cidr(request.cidr, request.authorized)
        else:
            if not request.authorized:
                raise ValueError('You must confirm that you are authorized to scan this network.')
            network = None
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    cidr = str(network) if network is not None else f"{target['resolved_ip']}/32"
    scan = Scan(
        id=uuid4(),
        cidr=cidr,
        target_type=target['type'],
        original_target=request.cidr,
        depth=request.depth,
        status='discovering',
        created_at=datetime.now(timezone.utc),
    )
    scans[scan.id] = scan
    if target['type'] == 'cidr':
        background_tasks.add_task(discover_scan_hosts, scan.id, scan.cidr)
    else:
        background_tasks.add_task(scan_single_host, scan.id, target['resolved_ip'])
    return scan


@app.get('/scans', response_model=list[ScanSummary])
def list_scans() -> list[ScanSummary]:
    return [
        ScanSummary(
            id=scan.id,
            cidr=scan.cidr,
            target_type=scan.target_type,
            original_target=scan.original_target,
            depth=scan.depth,
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


@app.get('/scans/{scan_id}/report.pdf')
def get_scan_report(scan_id: UUID) -> Response:
    scan = scans.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail='Scan not found.')
    if scan.status != 'completed':
        raise HTTPException(
            status_code=409,
            detail='Scan not finished - report unavailable until status is completed.',
        )

    return Response(
        content=build_report(scan),
        media_type='application/pdf',
        headers={'Content-Disposition': f'attachment; filename="recon-report-{scan_id}.pdf"'},
    )