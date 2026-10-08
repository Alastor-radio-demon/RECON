import logging

import httpx

from app.config import settings
from app.models import Host


logger = logging.getLogger(__name__)


def build_prompt(host: Host) -> str:
    ports = [f'{port.port}/{port.protocol} {port.service}' for port in host.ports]
    cves = [
        f'{cve.cve_id} ({cve.severity}) on port {port.port}'
        for port in host.ports
        for cve in port.cves
    ]
    vuln_findings = [
        f'{finding.script_id} [{finding.state}]'
        f'{f" on port {finding.port}" if finding.port is not None else ""}'
        f'{f"; CVEs: {", ".join(finding.cve_ids)}" if finding.cve_ids else ""}'
        for finding in host.vuln_findings
    ]
    web_findings = [
        f'{finding.name} ({finding.severity}, template {finding.template_id}) at {finding.matched_at}'
        for finding in host.web_findings
    ]

    def compact(items: list[str]) -> str:
        return '\n'.join(f'- {item}' for item in items) if items else '- None reported'

    return (
        'You are a defensive security advisor. Based only on the host findings below, '
        'provide 3-5 concise, prioritized hardening recommendations in plain language, '
        'ordered from most urgent to least urgent. Focus on practical remediation; do not '
        'provide exploit instructions.\n\n'
        f'Host: {host.ip}\n'
        f'OS: {host.os or "Unknown"}\n'
        f'Score: {host.score if host.score is not None else "Unknown"}; grade: {host.grade or "Unknown"}\n'
        f'Open ports and services:\n{compact(ports)}\n'
        f'CVEs:\n{compact(cves)}\n'
        f'NSE findings:\n{compact(vuln_findings)}\n'
        f'Web findings:\n{compact(web_findings)}\n'
        f'Risk factors:\n{compact(host.risk_reasons)}'
    )


async def get_recommendations(host: Host) -> str:
    try:
        url = f'{settings.OLLAMA_URL.rstrip("/")}/api/generate'
        payload = {
            'model': settings.OLLAMA_MODEL,
            'prompt': build_prompt(host),
            'stream': False,
            'keep_alive': '30m',
        }
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
            result = response.json()
        if not isinstance(result, dict) or not isinstance(result.get('response'), str):
            raise ValueError('Ollama response did not contain a string response field.')
        return result['response'].strip()
    except Exception:
        logger.exception('Ollama recommendations failed for host %s', host.ip)
        return ''