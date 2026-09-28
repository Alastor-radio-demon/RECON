import subprocess
import xml.etree.ElementTree as ET


def parse_discovery_xml(xml_output: str) -> list[dict[str, str | None]]:
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as exc:
        raise RuntimeError(f'Nmap returned invalid XML: {exc}') from exc

    hosts: list[dict[str, str | None]] = []
    for host in root.findall('host'):
        status = host.find('status')
        if status is None or status.get('state') != 'up':
            continue

        addresses = host.findall('address')
        address = next(
            (item for item in addresses if item.get('addrtype') == 'ipv4'),
            addresses[0] if addresses else None,
        )
        if address is None or address.get('addr') is None:
            continue

        hostname_element = host.find('hostnames/hostname')
        hostname = hostname_element.get('name') if hostname_element is not None else None
        hosts.append({'ip': address.get('addr'), 'hostname': hostname})

    return hosts


def run_discovery(cidr: str) -> list[dict[str, str | None]]:
    try:
        result = subprocess.run(
            ['nmap', '-sn', cidr, '-oX', '-'],
            capture_output=True,
            text=True,
            timeout=120,
            check=True,
        )
    except FileNotFoundError as exc:
        raise RuntimeError('Nmap was not found on PATH.') from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f'Nmap host discovery timed out for {cidr}.') from exc
    except subprocess.CalledProcessError as exc:
        details = exc.stderr.strip() or f'exited with status {exc.returncode}'
        raise RuntimeError(f'Nmap host discovery failed: {details}') from exc

    return parse_discovery_xml(result.stdout)