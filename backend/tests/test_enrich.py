import asyncio
import sqlite3
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
def reset_enrichment_state(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    monkeypatch.setattr(enrich, 'CACHE_DB_PATH', tmp_path / 'cve-cache.db')
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
        status_code = 200
        headers: dict[str, str] = {}

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
        status_code = 200
        headers: dict[str, str] = {}

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
    with sqlite3.connect(enrich.CACHE_DB_PATH) as connection:
        assert connection.execute(
            'SELECT cves FROM cve_cache WHERE product = ? AND version = ?',
            ('nginx', '1.24'),
        ).fetchone() == ('[]',)


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
        status_code = 200
        headers: dict[str, str] = {}

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, Any]:
            return NVD_RESPONSE

    monkeypatch.setattr(config.settings, 'NVD_API_KEY', None)
    monkeypatch.setattr(enrich.httpx, 'AsyncClient', MockAsyncClient)

    assert await enrich.lookup_cves('nginx', '1.24') == []
    assert await enrich.lookup_cves('nginx', '1.24')
    assert calls == 2


@pytest.mark.anyio
async def test_lookup_cves_retries_rate_limit_and_respects_retry_after(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0
    waits: list[float] = []

    class MockRateLimitResponse:
        status_code = 429
        headers = {'Retry-After': '7'}

    class MockSuccessResponse:
        status_code = 200
        headers: dict[str, str] = {}

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, Any]:
            return NVD_RESPONSE

    responses = [MockRateLimitResponse(), MockSuccessResponse()]

    class MockAsyncClient:
        def __init__(self, timeout: float) -> None:
            assert timeout == 10.0

        async def __aenter__(self) -> 'MockAsyncClient':
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

        async def get(self, *_: object, **__: object) -> Any:
            nonlocal calls
            response = responses[calls]
            calls += 1
            return response

    async def record_wait(delay: float) -> None:
        waits.append(delay)

    monkeypatch.setattr(config.settings, 'NVD_API_KEY', 'test-api-key')
    monkeypatch.setattr(enrich.httpx, 'AsyncClient', MockAsyncClient)
    monkeypatch.setattr(enrich.asyncio, 'sleep', record_wait)

    assert await enrich.lookup_cves('Apache httpd', '2.4.29')
    assert calls == 2
    assert waits == [7.0]


@pytest.mark.anyio
async def test_lookup_cves_stops_after_three_rate_limited_attempts_without_caching(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0
    waits: list[float] = []

    class MockRateLimitResponse:
        status_code = 429
        headers: dict[str, str] = {}

    class MockAsyncClient:
        def __init__(self, timeout: float) -> None:
            pass

        async def __aenter__(self) -> 'MockAsyncClient':
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

        async def get(self, *_: object, **__: object) -> MockRateLimitResponse:
            nonlocal calls
            calls += 1
            return MockRateLimitResponse()

    async def record_wait(delay: float) -> None:
        waits.append(delay)

    monkeypatch.setattr(config.settings, 'NVD_API_KEY', 'test-api-key')
    monkeypatch.setattr(enrich.httpx, 'AsyncClient', MockAsyncClient)
    monkeypatch.setattr(enrich.asyncio, 'sleep', record_wait)

    assert await enrich.lookup_cves('Apache httpd', '2.4.29') == []
    assert calls == 3
    assert waits == [2.0, 5.0]
    with sqlite3.connect(enrich.CACHE_DB_PATH) as connection:
        assert connection.execute(
            'SELECT cves FROM cve_cache WHERE product = ? AND version = ?',
            ('Apache httpd', '2.4.29'),
        ).fetchone() is None


@pytest.mark.anyio
async def test_successful_cache_survives_simulated_restart(
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
            return MockSuccessResponse()

    class MockSuccessResponse:
        status_code = 200
        headers: dict[str, str] = {}

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, Any]:
            return NVD_RESPONSE

    monkeypatch.setattr(config.settings, 'NVD_API_KEY', 'test-api-key')
    monkeypatch.setattr(enrich.httpx, 'AsyncClient', MockAsyncClient)

    first_result = await enrich.lookup_cves('Apache httpd', '2.4.29')
    monkeypatch.setattr(enrich, '_request_semaphore', asyncio.Semaphore(1))
    monkeypatch.setattr(enrich, '_last_request_at', None)
    monkeypatch.setattr(enrich.httpx, 'AsyncClient', lambda **_: pytest.fail('cache should avoid a network request'))

    assert await enrich.lookup_cves('Apache httpd', '2.4.29') == first_result
    assert calls == 1


@pytest.mark.anyio
async def test_zero_result_cache_expires_but_nonempty_cache_does_not(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = [1_000_000.0]
    calls: dict[str, int] = {'zero 1': 0, 'nonempty 1': 0}

    class MockAsyncClient:
        def __init__(self, timeout: float) -> None:
            pass

        async def __aenter__(self) -> 'MockAsyncClient':
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

        async def get(self, _: str, *, params: dict[str, Any], **__: object) -> Any:
            query = params['keywordSearch']
            calls[query] += 1
            return MockZeroResponse() if query == 'zero 1' else MockSuccessResponse()

    class MockZeroResponse:
        status_code = 200
        headers: dict[str, str] = {}

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, Any]:
            return {'totalResults': 0, 'vulnerabilities': []}

    class MockSuccessResponse:
        status_code = 200
        headers: dict[str, str] = {}

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, Any]:
            return NVD_RESPONSE

    monkeypatch.setattr(config.settings, 'NVD_API_KEY', 'test-api-key')
    monkeypatch.setattr(enrich, '_now', lambda: now[0])
    monkeypatch.setattr(enrich.httpx, 'AsyncClient', MockAsyncClient)

    assert await enrich.lookup_cves('zero', '1') == []
    assert await enrich.lookup_cves('nonempty', '1')
    now[0] += enrich.EMPTY_RESULT_CACHE_TTL - 1
    assert await enrich.lookup_cves('zero', '1') == []
    now[0] += 2
    assert await enrich.lookup_cves('zero', '1') == []
    now[0] += enrich.EMPTY_RESULT_CACHE_TTL * 10
    assert await enrich.lookup_cves('nonempty', '1')
    assert calls == {'zero 1': 2, 'nonempty 1': 1}