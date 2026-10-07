import asyncio
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app import config, main
from app.models import Host, Scan


def test_list_scans_returns_summaries_newest_first(monkeypatch: pytest.MonkeyPatch) -> None:
    created_at_values = iter([
        datetime(2026, 9, 29, 10, 0, tzinfo=timezone.utc),
        datetime(2026, 9, 29, 10, 1, tzinfo=timezone.utc),
    ])

    class FixedDateTime:
        @staticmethod
        def now(tz: timezone | None = None) -> datetime:
            return next(created_at_values)

    monkeypatch.setattr(config.settings, 'lab_mode', True)
    monkeypatch.setattr(main, 'datetime', FixedDateTime)
    monkeypatch.setattr(main, 'scans', {})
    discovery_count = 0

    async def complete_scan(scan_id: object, _: str) -> None:
        nonlocal discovery_count
        scan = main.scans[scan_id]
        scan.status = 'completed'
        scan.hosts = [Host(ip=f'192.168.1.{index + 1}') for index in range(discovery_count + 1)]
        scan.network_score = 80
        scan.network_grade = 'B'
        discovery_count += 1

    monkeypatch.setattr(main, 'discover_scan_hosts', complete_scan)

    with TestClient(main.app) as client:
        first_response = client.post('/scans', json={'cidr': '192.168.1.0/24', 'authorized': True})
        second_response = client.post('/scans', json={'cidr': '192.168.1.0/24', 'authorized': True})
        response = client.get('/scans')

    assert first_response.status_code == 201
    assert second_response.status_code == 201
    assert response.status_code == 200
    summaries = response.json()
    assert [summary['id'] for summary in summaries] == [
        second_response.json()['id'],
        first_response.json()['id'],
    ]
    assert summaries == [
        {
            'id': second_response.json()['id'],
            'cidr': '192.168.1.0/24',
            'target_type': 'cidr',
            'original_target': '192.168.1.0/24',
            'status': 'completed',
            'created_at': '2026-09-29T10:01:00Z',
            'network_score': 80,
            'network_grade': 'B',
            'host_count': 2,
        },
        {
            'id': first_response.json()['id'],
            'cidr': '192.168.1.0/24',
            'target_type': 'cidr',
            'original_target': '192.168.1.0/24',
            'status': 'completed',
            'created_at': '2026-09-29T10:00:00Z',
            'network_score': 80,
            'network_grade': 'B',
            'host_count': 1,
        },
    ]


def test_vulnscan_timeout_finishes_host_before_completing_scan(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    scan_id = uuid4()
    scan = Scan(
        id=scan_id,
        cidr='192.168.1.0/24',
        status='discovering',
        created_at=datetime.now(timezone.utc),
    )
    monkeypatch.setattr(main, 'scans', {scan_id: scan})
    monkeypatch.setattr(main, 'run_discovery', lambda _: [{'ip': '192.168.1.10', 'hostname': None}])
    monkeypatch.setattr(main, 'run_portscan', lambda _: {'ports': []})
    scan_status_during_vulnscan: list[str] = []

    def timeout_vulnscan(_: str) -> list[dict]:
        scan_status_during_vulnscan.append(scan.status)
        raise RuntimeError('Nmap vulnerability scan timed out for 192.168.1.10.')

    monkeypatch.setattr(main, 'run_vulnscan', timeout_vulnscan)

    asyncio.run(main.discover_scan_hosts(scan_id, scan.cidr))

    assert scan_status_during_vulnscan == ['discovering']
    assert scan.status == 'completed'
    assert scan.hosts[0].status == 'done'
    assert scan.hosts[0].vuln_findings == []
    assert (scan.network_score, scan.network_grade) == (100, 'A')
    assert 'Nmap vulnerability scan failed for host 192.168.1.10' in caplog.text


def test_url_scan_skips_discovery_and_scans_resolved_host(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config.settings, 'lab_mode', False)
    monkeypatch.setattr(main, 'scans', {})
    monkeypatch.setattr('app.scope.socket.gethostbyname', lambda _: '8.8.8.8')
    monkeypatch.setattr(main, 'run_discovery', lambda _: pytest.fail('URL scans must skip discovery'))
    monkeypatch.setattr(main, 'run_portscan', lambda _: {'ports': []})
    monkeypatch.setattr(main, 'run_vulnscan', lambda _: [])

    with TestClient(main.app) as client:
        response = client.post(
            '/scans',
            json={'cidr': 'https://example.com/path', 'authorized': True},
        )
        scan_response = client.get(f"/scans/{response.json()['id']}")

    assert response.status_code == 201
    assert response.json()['target_type'] == 'url'
    assert response.json()['original_target'] == 'https://example.com/path'
    assert scan_response.json()['cidr'] == '8.8.8.8/32'
    assert scan_response.json()['status'] == 'completed'
    assert scan_response.json()['hosts'][0]['ip'] == '8.8.8.8'
    assert scan_response.json()['hosts'][0]['status'] == 'done'