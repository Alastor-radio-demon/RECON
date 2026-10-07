from datetime import datetime, timezone
from uuid import uuid4

from fastapi.testclient import TestClient

from app import main
from app.models import CVE, Host, Port, Scan, VulnScriptFinding, WebFinding
from app.reporting.pdf_report import build_report


def sample_scan(status: str = 'completed') -> Scan:
    return Scan(
        id=uuid4(),
        cidr='192.0.2.0/24',
        target_type='cidr',
        original_target='192.0.2.0/24',
        status=status,
        created_at=datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc),
        network_score=72,
        network_grade='C',
        hosts=[
            Host(
                ip='192.0.2.10',
                hostname='app.example.test',
                status='done',
                ports=[Port(
                    port=443,
                    protocol='tcp',
                    service='https',
                    product='Example Server',
                    version='1.2',
                    cves=[CVE(
                        cve_id='CVE-2025-12345',
                        description='A sample remotely exploitable issue.',
                        cvss=9.1,
                        severity='critical',
                    )],
                )],
                score=45,
                grade='F',
                risk_reasons=['Critical CVE on port 443'],
            ),
            Host(ip='192.0.2.11', status='done', score=100, grade='A'),
            Host(
                ip='192.0.2.12',
                status='done',
                vuln_findings=[VulnScriptFinding(
                    script_id='http-vuln-sample',
                    port=8080,
                    output='VULNERABLE: sample service requires an update.',
                    cve_ids=['CVE-2024-98765'],
                    state='VULNERABLE',
                )],
                web_findings=[WebFinding(
                    template_id='exposed-panel',
                    name='Exposed admin panel',
                    severity='high',
                    description='An administrative interface is publicly reachable.',
                    matched_at='http://192.0.2.12:8080/admin',
                )],
                score=60,
                grade='D',
            ),
        ],
    )


def test_build_report_returns_pdf_for_mixed_scan_findings() -> None:
    pdf = build_report(sample_scan())

    assert pdf.startswith(b'%PDF')
    assert len(pdf) > 1000


def test_build_report_handles_scan_with_no_hosts() -> None:
    scan = sample_scan()
    scan.hosts = []

    pdf = build_report(scan)

    assert pdf.startswith(b'%PDF')


def test_report_endpoint_handles_missing_incomplete_and_completed_scans(
    monkeypatch,
) -> None:
    completed = sample_scan()
    incomplete = sample_scan(status='discovering')
    monkeypatch.setattr(main, 'scans', {completed.id: completed, incomplete.id: incomplete})

    with TestClient(main.app) as client:
        missing_response = client.get(f'/scans/{uuid4()}/report.pdf')
        incomplete_response = client.get(f'/scans/{incomplete.id}/report.pdf')
        completed_response = client.get(f'/scans/{completed.id}/report.pdf')

    assert missing_response.status_code == 404
    assert incomplete_response.status_code == 409
    assert 'report unavailable until status is completed' in incomplete_response.json()['detail']
    assert completed_response.status_code == 200
    assert completed_response.headers['content-type'] == 'application/pdf'
    assert completed_response.headers['content-disposition'] == f'attachment; filename="recon-report-{completed.id}.pdf"'
    assert completed_response.content.startswith(b'%PDF')