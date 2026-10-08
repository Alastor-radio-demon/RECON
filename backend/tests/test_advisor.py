import asyncio
from typing import Any

import httpx
import pytest

from app import config, main
from app.models import CVE, Host, Port, VulnScriptFinding, WebFinding
from app.scanner import advisor


def sample_host() -> Host:
    return Host(
        ip='192.0.2.10',
        hostname='app.example.test',
        os='Linux',
        ports=[Port(
            port=443,
            protocol='tcp',
            service='https',
            cves=[CVE(
                cve_id='CVE-2025-12345',
                description='A long description that should not appear in the compact prompt.',
                cvss=9.1,
                severity='critical',
            )],
        )],
        vuln_findings=[VulnScriptFinding(
            script_id='http-vuln-example',
            port=443,
            output='VULNERABLE: update the affected component.',
            cve_ids=['CVE-2025-12345'],
            state='VULNERABLE',
        )],
        web_findings=[WebFinding(
            template_id='exposed-admin',
            name='Exposed admin console',
            severity='high',
            description='Admin console is publicly reachable.',
            matched_at='https://192.0.2.10/admin',
        )],
        score=50,
        grade='F',
        risk_reasons=['HTTPS service exposes a critical CVE'],
    )


def test_build_prompt_summarizes_host_findings_compactly() -> None:
    prompt = advisor.build_prompt(sample_host())

    assert '192.0.2.10' in prompt
    assert 'OS: Linux' in prompt
    assert '443/tcp https' in prompt
    assert 'CVE-2025-12345 (critical)' in prompt
    assert 'http-vuln-example [VULNERABLE]' in prompt
    assert 'Exposed admin console (high, template exposed-admin)' in prompt
    assert 'HTTPS service exposes a critical CVE' in prompt
    assert '3-5 concise, prioritized hardening recommendations' in prompt
    assert 'long description' not in prompt


def test_get_recommendations_posts_to_configured_ollama_and_returns_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[dict[str, Any]] = []

    class MockResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, str]:
            return {'response': '1. Patch the affected HTTPS service.'}

    class MockAsyncClient:
        def __init__(self, timeout: float) -> None:
            assert timeout == 60.0

        async def __aenter__(self) -> 'MockAsyncClient':
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

        async def post(self, url: str, *, json: dict[str, Any]) -> MockResponse:
            requests.append({'url': url, 'json': json})
            return MockResponse()

    monkeypatch.setattr(config.settings, 'OLLAMA_URL', 'http://ollama.test/')
    monkeypatch.setattr(config.settings, 'OLLAMA_MODEL', 'test-model')
    monkeypatch.setattr(advisor.httpx, 'AsyncClient', MockAsyncClient)

    result = asyncio.run(advisor.get_recommendations(sample_host()))

    assert result == '1. Patch the affected HTTPS service.'
    assert requests == [{
        'url': 'http://ollama.test/api/generate',
        'json': {
            'model': 'test-model',
            'prompt': advisor.build_prompt(sample_host()),
            'stream': False,
            'keep_alive': '30m',
        },
    }]


@pytest.mark.parametrize(
    'error',
    [
        httpx.TimeoutException('request timed out'),
        httpx.ConnectError('connection refused'),
    ],
)
def test_get_recommendations_returns_empty_for_request_errors(
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
) -> None:
    class MockAsyncClient:
        def __init__(self, timeout: float) -> None:
            pass

        async def __aenter__(self) -> 'MockAsyncClient':
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

        async def post(self, *_: object, **__: object) -> None:
            raise error

    monkeypatch.setattr(advisor.httpx, 'AsyncClient', MockAsyncClient)

    assert asyncio.run(advisor.get_recommendations(sample_host())) == ''


def test_get_recommendations_returns_empty_for_malformed_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class MockResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, Any]:
            return {'response': None}

    class MockAsyncClient:
        def __init__(self, timeout: float) -> None:
            pass

        async def __aenter__(self) -> 'MockAsyncClient':
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

        async def post(self, *_: object, **__: object) -> MockResponse:
            return MockResponse()

    monkeypatch.setattr(advisor.httpx, 'AsyncClient', MockAsyncClient)

    assert asyncio.run(advisor.get_recommendations(sample_host())) == ''


def test_scan_host_requests_recommendations_only_in_full_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requested_hosts: list[Host] = []

    async def recommendations(host: Host) -> str:
        requested_hosts.append(host)
        return 'Patch exposed services first.'

    monkeypatch.setattr(main, 'run_portscan', lambda _: {'ports': []})
    monkeypatch.setattr(main, 'run_vulnscan', lambda _: [])
    monkeypatch.setattr(main, 'run_nuclei', lambda _: [])
    monkeypatch.setattr(main, 'get_recommendations', recommendations)
    full_host = Host(ip='192.0.2.20')
    quick_host = Host(ip='192.0.2.21')

    asyncio.run(main.scan_host(full_host, depth='full'))
    asyncio.run(main.scan_host(quick_host, depth='quick'))

    assert requested_hosts == [full_host]
    assert full_host.ai_recommendations == 'Patch exposed services first.'
    assert quick_host.ai_recommendations == ''