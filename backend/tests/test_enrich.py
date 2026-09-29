from typing import Any

import pytest

from app import config
from app.scanner import enrich


NVD_RESPONSE = {
    'resultsPerPage': 5,
    'totalResults': 3,
    'vulnerabilities': [
        {
            'cve': {
                'id': 'CVE-2024-12345',
                'descriptions': [{'lang': 'en', 'value': 'A critical sample vulnerability.'}],
                'metrics': {
                    'cvssMetricV31': [
                        {'cvssData': {'baseScore': 9.8}},
                    ],
                },
            },
        },
        {
            'cve': {
                'id': 'CVE-2024-67890',
                'descriptions': [{'lang': 'en', 'value': 'B' * 240}],
                'metrics': {
                    'cvssMetricV30': [
                        {'cvssData': {'baseScore': 6.5}},
                    ],
                },
            },
        },
        {
            'cve': {
                'id': 'CVE-2024-99999',
                'descriptions': [{'lang': 'en', 'value': 'No score available.'}],
                'metrics': {},
            },
        },
    ],
}


@pytest.fixture(autouse=True)
def reset_enrichment_state(monkeypatch: pytest.MonkeyPatch) -> None:
    enrich._cve_cache.clear()
    monkeypatch.setattr(enrich, '_last_request_at', None)

    async def no_wait(_: float) -> None:
        return None

    monkeypatch.setattr(enrich.asyncio, 'sleep', no_wait)


@pytest.fixture
def anyio_backend() -> str:
    return 'asyncio'


def test_build_cpe_query_joins_trimmed_product_and_version() -> None:
    assert enrich.build_cpe_query('  OpenSSH ', ' 9.6 ') == 'OpenSSH 9.6'


@pytest.mark.anyio
async def test_lookup_cves_parses_mocked_nvd_response_and_caches_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, Any]] = []

    class MockResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, Any]:
            return NVD_RESPONSE

    class MockAsyncClient:
        def __init__(self, timeout: float) -> None:
            assert timeout == 10.0

        async def __aenter__(self) -> 'MockAsyncClient':
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

        async def get(self, url: str, *, params: dict[str, Any], headers: dict[str, str] | None) -> MockResponse:
            calls.append({'url': url, 'params': params, 'headers': headers})
            return MockResponse()

    monkeypatch.setattr(config.settings, 'NVD_API_KEY', 'test-api-key')
    monkeypatch.setattr(enrich.httpx, 'AsyncClient', MockAsyncClient)

    expected = [
        {
            'cve_id': 'CVE-2024-12345',
            'description': 'A critical sample vulnerability.',
            'cvss': 9.8,
            'severity': 'critical',
        },
        {
            'cve_id': 'CVE-2024-67890',
            'description': 'B' * 200,
            'cvss': 6.5,
            'severity': 'medium',
        },
        {
            'cve_id': 'CVE-2024-99999',
            'description': 'No score available.',
            'cvss': None,
            'severity': 'low',
        },
    ]

    assert await enrich.lookup_cves('OpenSSH', '9.6') == expected
    assert await enrich.lookup_cves('OpenSSH', '9.6') == expected
    assert len(calls) == 1
    assert calls[0] == {
        'url': enrich.NVD_API_URL,
        'params': {'keywordSearch': 'OpenSSH 9.6', 'resultsPerPage': 5},
        'headers': {'apiKey': 'test-api-key'},
    }


@pytest.mark.anyio
async def test_lookup_cves_caches_genuine_zero_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    class MockResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, Any]:
            return {'totalResults': 0, 'vulnerabilities': []}

    class MockAsyncClient:
        def __init__(self, timeout: float) -> None:
            pass

        async def __aenter__(self) -> 'MockAsyncClient':
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

        async def get(self, *_: object, **__: object) -> MockResponse:
            nonlocal calls
            calls += 1
            return MockResponse()

    monkeypatch.setattr(config.settings, 'NVD_API_KEY', None)
    monkeypatch.setattr(enrich.httpx, 'AsyncClient', MockAsyncClient)

    assert await enrich.lookup_cves('nginx', '1.24') == []
    assert await enrich.lookup_cves('nginx', '1.24') == []
    assert calls == 1
    assert enrich._cve_cache['nginx:1.24'][1] is not None


@pytest.mark.anyio
async def test_lookup_cves_retries_after_error_instead_of_caching_miss(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    class MockAsyncClient:
        def __init__(self, timeout: float) -> None:
            pass

        async def __aenter__(self) -> 'MockAsyncClient':
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

        async def get(self, *_: object, **__: object) -> Any:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise TimeoutError('request timed out')
            return MockResponse()

    class MockResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, Any]:
            return NVD_RESPONSE

    monkeypatch.setattr(config.settings, 'NVD_API_KEY', None)
    monkeypatch.setattr(enrich.httpx, 'AsyncClient', MockAsyncClient)

    assert await enrich.lookup_cves('nginx', '1.24') == []
    assert await enrich.lookup_cves('nginx', '1.24')
    assert calls == 2