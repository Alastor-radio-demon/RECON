import asyncio
import json
import logging
import sqlite3
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any

import httpx

from app.config import settings


NVD_API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
EMPTY_RESULT_CACHE_TTL = 300.0
CACHE_DB_PATH = Path(__file__).resolve().parents[2] / 'data' / 'cve_cache.db'
RATE_LIMIT_STATUS_CODES = {403, 429}
RATE_LIMIT_BACKOFFS = (2.0, 5.0)
MAX_RATE_LIMIT_ATTEMPTS = 3
_request_semaphore = asyncio.Semaphore(1)
_last_request_at: float | None = None
logger = logging.getLogger(__name__)


def build_cpe_query(product: str, version: str) -> str:
    return ' '.join(value.strip() for value in (product, version) if value.strip())


def _severity_for_cvss(cvss: float | None) -> str:
    if cvss is None:
        return 'low'
    if cvss >= 9:
        return 'critical'
    if cvss >= 7:
        return 'high'
    if cvss >= 4:
        return 'medium'
    return 'low'


def _parse_nvd_response(data: Any) -> list[dict[str, Any]]:
    if not isinstance(data, dict) or not isinstance(data.get('vulnerabilities'), list):
        raise ValueError('NVD response has no vulnerabilities list.')

    results: list[dict[str, Any]] = []
    for item in data['vulnerabilities']:
        cve = item.get('cve') if isinstance(item, dict) else None
        if not isinstance(cve, dict) or not isinstance(cve.get('id'), str):
            raise ValueError('NVD response contains an invalid CVE entry.')

        descriptions = cve.get('descriptions', [])
        description = next(
            (
                entry.get('value', '')
                for entry in descriptions
                if isinstance(entry, dict) and entry.get('lang') == 'en'
            ),
            '',
        )
        if not isinstance(description, str):
            description = ''

        cvss: float | None = None
        metrics = cve.get('metrics', {})
        if isinstance(metrics, dict):
            for metric_name in ('cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
                metric_entries = metrics.get(metric_name, [])
                if not isinstance(metric_entries, list):
                    continue
                for metric in metric_entries:
                    cvss_data = metric.get('cvssData') if isinstance(metric, dict) else None
                    base_score = cvss_data.get('baseScore') if isinstance(cvss_data, dict) else None
                    if base_score is not None:
                        cvss = float(base_score)
                        break
                if cvss is not None:
                    break

        results.append(
            {
                'cve_id': cve['id'],
                'description': description,
                'cvss': cvss,
                'severity': _severity_for_cvss(cvss),
            }
        )

    return results


def _open_cache_db() -> sqlite3.Connection:
    CACHE_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(CACHE_DB_PATH, timeout=30.0)
    connection.execute(
        'CREATE TABLE IF NOT EXISTS cve_cache ('
        'product TEXT NOT NULL, '
        'version TEXT NOT NULL, '
        'cves TEXT NOT NULL, '
        'fetched_at REAL NOT NULL, '
        'PRIMARY KEY (product, version))'
    )
    return connection


def _now() -> float:
    return time.time()


def _get_cached_result(product: str, version: str, now: float) -> list[dict[str, Any]] | None:
    connection = _open_cache_db()
    try:
        row = connection.execute(
            'SELECT cves, fetched_at FROM cve_cache WHERE product = ? AND version = ?',
            (product, version),
        ).fetchone()
        if row is None:
            return None

        try:
            result = json.loads(row[0])
            if not isinstance(result, list):
                raise ValueError('Cached CVE payload is not a list.')
        except (json.JSONDecodeError, TypeError, ValueError):
            connection.execute('DELETE FROM cve_cache WHERE product = ? AND version = ?', (product, version))
            connection.commit()
            return None

        fetched_at = float(row[1])
        if not result and now - fetched_at >= EMPTY_RESULT_CACHE_TTL:
            connection.execute('DELETE FROM cve_cache WHERE product = ? AND version = ?', (product, version))
            connection.commit()
            return None
        return result
    finally:
        connection.close()


def _store_cached_result(product: str, version: str, result: list[dict[str, Any]], fetched_at: float) -> None:
    connection = _open_cache_db()
    try:
        connection.execute(
            'INSERT INTO cve_cache (product, version, cves, fetched_at) VALUES (?, ?, ?, ?) '
            'ON CONFLICT(product, version) DO UPDATE SET cves = excluded.cves, fetched_at = excluded.fetched_at',
            (product, version, json.dumps(result), fetched_at),
        )
        connection.commit()
    finally:
        connection.close()


def _retry_after_seconds(response: httpx.Response) -> float | None:
    retry_after = response.headers.get('Retry-After')
    if not retry_after:
        return None

    try:
        return max(0.0, float(retry_after))
    except ValueError:
        try:
            retry_at = parsedate_to_datetime(retry_after)
        except (TypeError, ValueError, OverflowError):
            return None
        if retry_at.tzinfo is None:
            retry_at = retry_at.replace(tzinfo=timezone.utc)
        return max(0.0, (retry_at - datetime.now(timezone.utc)).total_seconds())


async def lookup_cves(product: str, version: str) -> list[dict[str, Any]]:
    global _last_request_at

    loop = asyncio.get_running_loop()
    cached_result = _get_cached_result(product, version, _now())
    if cached_result is not None:
        return cached_result

    async with _request_semaphore:
        cached_result = _get_cached_result(product, version, _now())
        if cached_result is not None:
            return cached_result

        delay = 0.6 if settings.NVD_API_KEY else 6.0
        if _last_request_at is not None:
            elapsed = loop.time() - _last_request_at
            if elapsed < delay:
                await asyncio.sleep(delay - elapsed)

        headers = {'apiKey': settings.NVD_API_KEY} if settings.NVD_API_KEY else None
        cache_success = False
        cache_key = f'{product}:{version}'
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                for attempt in range(1, MAX_RATE_LIMIT_ATTEMPTS + 1):
                    response = await client.get(
                        NVD_API_URL,
                        params={
                            'keywordSearch': build_cpe_query(product, version),
                            'resultsPerPage': 5,
                        },
                        headers=headers,
                    )
                    _last_request_at = loop.time()
                    if response.status_code in RATE_LIMIT_STATUS_CODES:
                        if attempt == MAX_RATE_LIMIT_ATTEMPTS:
                            raise RuntimeError(f'NVD rate limit retries exhausted after {attempt} attempts.')
                        retry_after = _retry_after_seconds(response)
                        wait_seconds = retry_after if retry_after is not None else RATE_LIMIT_BACKOFFS[attempt - 1]
                        logger.warning(
                            'NVD rate limited, retrying in %ss (attempt %s/%s) for %s',
                            wait_seconds,
                            attempt + 1,
                            MAX_RATE_LIMIT_ATTEMPTS,
                            cache_key,
                        )
                        await asyncio.sleep(wait_seconds)
                        continue

                    response.raise_for_status()
                    data = response.json()
                    result = _parse_nvd_response(data)
                    if not result:
                        total_results = data.get('totalResults') if isinstance(data, dict) else None
                        if type(total_results) is not int or total_results != 0:
                            raise ValueError('NVD empty response did not report totalResults: 0.')
                    cache_success = True
                    break
                else:
                    raise RuntimeError('NVD rate limit retries exhausted.')
        except Exception as exc:
            logger.warning('NVD CVE lookup failed for %s: %s', cache_key, exc)
            result = []
        finally:
            _last_request_at = loop.time()

        if cache_success:
            _store_cached_result(product, version, result, _now())
        return result