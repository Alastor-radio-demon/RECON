import asyncio
import logging
from typing import Any

import httpx

from app.config import settings


NVD_API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
_cve_cache: dict[str, list[dict[str, Any]]] = {}
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
                'description': description[:200],
                'cvss': cvss,
                'severity': _severity_for_cvss(cvss),
            }
        )

    return results


async def lookup_cves(product: str, version: str) -> list[dict[str, Any]]:
    global _last_request_at

    cache_key = f'{product}:{version}'
    if cache_key in _cve_cache:
        return _cve_cache[cache_key]

    async with _request_semaphore:
        if cache_key in _cve_cache:
            return _cve_cache[cache_key]

        delay = 0.6 if settings.NVD_API_KEY else 6.0
        loop = asyncio.get_running_loop()
        if _last_request_at is not None:
            elapsed = loop.time() - _last_request_at
            if elapsed < delay:
                await asyncio.sleep(delay - elapsed)

        headers = {'apiKey': settings.NVD_API_KEY} if settings.NVD_API_KEY else None
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(
                    NVD_API_URL,
                    params={
                        'keywordSearch': build_cpe_query(product, version),
                        'resultsPerPage': 5,
                    },
                    headers=headers,
                )
            response.raise_for_status()
            result = _parse_nvd_response(response.json())
        except Exception as exc:
            logger.warning('NVD CVE lookup failed for %s: %s', cache_key, exc)
            result = []
        finally:
            _last_request_at = loop.time()

        _cve_cache[cache_key] = result
        return result