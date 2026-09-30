import re
import subprocess
import xml.etree.ElementTree as ET


CVE_PATTERN = re.compile(r'\bCVE-\d{4}-\d{4,}\b', re.IGNORECASE)


def parse_vulnscan_xml(xml_output: str) -> list[dict[str, int | str | None | list[str]]]:
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as exc:
        raise RuntimeError(f'Nmap returned invalid XML: {exc}') from exc

    findings: list[dict[str, int | str | None | list[str]]] = []
    for host in root.findall('host'):
        scripts = [
            (script, int(port.get('portid', '0')))
            for port in host.findall('ports/port')
            for script in port.findall('script')
        ]
        scripts.extend((script, None) for script in host.findall('hostscript/script'))

        for script, port_number in scripts:
            script_id = script.get('id', '')
            if 'vuln' not in script_id.lower():
                continue

            output = script.get('output', '')
            cve_ids = list(dict.fromkeys(
                match.upper() for match in CVE_PATTERN.findall(output)
            ))
            findings.append(
                {
                    'script_id': script_id,
                    'port': port_number,
                    'output': output,
                    'cve_ids': cve_ids,
                    'state': (
                        'VULNERABLE'
                        if 'VULNERABLE' in output.upper() and 'NOT VULNERABLE' not in output.upper()
                        else 'INFO'
                    ),
                }
            )

    return findings


def run_vulnscan(ip: str) -> list[dict[str, int | str | None | list[str]]]:
    try:
        result = subprocess.run(
            ['nmap', '--script', 'vuln', '-oX', '-', ip],
            capture_output=True,
            text=True,
            timeout=180,
            check=True,
        )
    except FileNotFoundError as exc:
        raise RuntimeError('Nmap was not found on PATH.') from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f'Nmap vulnerability scan timed out for {ip}.') from exc
    except subprocess.CalledProcessError as exc:
        details = exc.stderr.strip() or f'exited with status {exc.returncode}'
        raise RuntimeError(f'Nmap vulnerability scan failed for {ip}: {details}') from exc

    return parse_vulnscan_xml(result.stdout)