import subprocess
import xml.etree.ElementTree as ET


def parse_portscan_xml(xml_output: str) -> dict[str, list[dict[str, int | str | None]]]:
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as exc:
        raise RuntimeError(f'Nmap returned invalid XML: {exc}') from exc

    ports: list[dict[str, int | str | None]] = []
    for port_element in root.findall('host/ports/port'):
        state_element = port_element.find('state')
        if state_element is None or state_element.get('state') != 'open':
            continue

        service_element = port_element.find('service')
        ports.append(
            {
                'port': int(port_element.get('portid', '0')),
                'protocol': port_element.get('protocol', ''),
                'state': 'open',
                'service': service_element.get('name', '') if service_element is not None else '',
                'product': service_element.get('product') if service_element is not None else None,
                'version': service_element.get('version') if service_element is not None else None,
            }
        )

    return {'ports': ports}


def run_portscan(ip: str) -> dict[str, list[dict[str, int | str | None]]]:
    try:
        result = subprocess.run(
            ['nmap', '-sV', '-T4', '--top-ports', '100', '-oX', '-', ip],
            capture_output=True,
            text=True,
            timeout=90,
            check=True,
        )
    except FileNotFoundError as exc:
        raise RuntimeError('Nmap was not found on PATH.') from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f'Nmap port scan timed out for {ip}.') from exc
    except subprocess.CalledProcessError as exc:
        details = exc.stderr.strip() or f'exited with status {exc.returncode}'
        raise RuntimeError(f'Nmap port scan failed for {ip}: {details}') from exc

    return parse_portscan_xml(result.stdout)