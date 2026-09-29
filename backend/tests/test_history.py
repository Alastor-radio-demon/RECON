from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app import config, main
from app.models import Host


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
            'status': 'completed',
            'created_at': '2026-09-29T10:01:00Z',
            'network_score': 80,
            'network_grade': 'B',
            'host_count': 2,
        },
        {
            'id': first_response.json()['id'],
            'cidr': '192.168.1.0/24',
            'status': 'completed',
            'created_at': '2026-09-29T10:00:00Z',
            'network_score': 80,
            'network_grade': 'B',
            'host_count': 1,
        },
    ]