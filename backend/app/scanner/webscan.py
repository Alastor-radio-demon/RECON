import json
import logging
import re
import subprocess
import threading
from typing import Any


logger = logging.getLogger(__name__)
CVE_PATTERN = re.compile(r'\bCVE-\d{4}-\d{4,}\b', re.IGNORECASE)
_missing_nuclei_warned = False
_warning_lock = threading.Lock()


def _as_string(value: Any) -> str:
    return value if isinstance(value, str) else ''


def _references(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [reference for reference in value if isinstance(reference, str)]
    return []


def _classification_cves(classification: Any) -> list[str]:
    if not isinstance(classification, dict):
        return []

    cve_value = classification.get('cve-id')
    if isinstance(cve_value, str):
        candidates = CVE_PATTERN.findall(cve_value)
    elif isinstance(cve_value, list):
        candidates = [
            match
            for value in cve_value
            if isinstance(value, str)
            for match in CVE_PATTERN.findall(value)
        ]
    else:
        candidates = []
    return list(dict.fromkeys(cve.upper() for cve in candidates))


def parse_nuclei_jsonl(jsonl_output: str) -> list[dict[str, str | None | list[str]]]:
    findings: list[dict[str, str | None | list[str]]] = []
    for line in jsonl_output.splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, dict):
            continue

        info = record.get('info')
        if not isinstance(info, dict):
            info = {}
        name = _as_string(info.get('name'))
        description = _as_string(info.get('description')) or None
        cve_ids = _classification_cves(info.get('classification'))
        if not cve_ids:
            cve_ids = list(dict.fromkeys(
                cve.upper()
                for cve in CVE_PATTERN.findall(f'{name} {description or ""}')
            ))

        findings.append(
            {
                'template_id': _as_string(record.get('template-id')),
                'name': name,
                'severity': _as_string(info.get('severity')),
                'description': description,
                'matched_at': _as_string(record.get('matched-at')),
                'reference': _references(info.get('reference')),
                'cve_ids': cve_ids,
            }
        )
    return findings


def run_nuclei(target_url: str) -> list[dict[str, str | None | list[str]]]:
    global _missing_nuclei_warned

    try:
        result = subprocess.run(
            [
                'nuclei', '-u', target_url, '-jsonl', '-silent',
                '-severity', 'low,medium,high,critical',
            ],
            capture_output=True,
            text=True,
            timeout=180,
            check=True,
        )
    except FileNotFoundError:
        with _warning_lock:
            if not _missing_nuclei_warned:
                logger.warning('Nuclei was not found on PATH; web vulnerability scans are disabled.')
                _missing_nuclei_warned = True
        return []
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f'Nuclei web scan timed out for {target_url}.') from exc
    except subprocess.CalledProcessError as exc:
        details = exc.stderr.strip() or f'exited with status {exc.returncode}'
        raise RuntimeError(f'Nuclei web scan failed for {target_url}: {details}') from exc

    return parse_nuclei_jsonl(result.stdout)