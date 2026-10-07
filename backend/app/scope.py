import ipaddress
import re
import socket
from ipaddress import IPv4Network, IPv6Network
from urllib.parse import urlsplit

from app.config import settings


Network = IPv4Network | IPv6Network
_HOSTNAME_PATTERN = re.compile(
    r'^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+'
    r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$'
)

_ALWAYS_BLOCKED = tuple(
    ipaddress.ip_network(value)
    for value in (
        '0.0.0.0/8',
        '127.0.0.0/8',
        '169.254.0.0/16',
        '192.0.0.0/24',
        '192.0.2.0/24',
        '198.18.0.0/15',
        '198.51.100.0/24',
        '203.0.113.0/24',
        '224.0.0.0/4',
        '240.0.0.0/4',
        '::/128',
        '::1/128',
        '::ffff:0:0/96',
        '64:ff9b:1::/48',
        '100::/64',
        '2001:db8::/32',
        '2002::/16',
        '3fff::/20',
        'ff00::/8',
    )
)


def validate_cidr(cidr: str, authorized: bool) -> Network:
    if not authorized:
        raise ValueError('You must confirm that you are authorized to scan this network.')

    try:
        network = ipaddress.ip_network(cidr, strict=True)
    except ValueError as exc:
        raise ValueError(f'Invalid CIDR network: {exc}') from exc

    if network.prefixlen < settings.max_prefix:
        raise ValueError(f'Network is too large; prefix length must be /{settings.max_prefix} or longer.')

    if any(network.version == blocked.version and network.overlaps(blocked) for blocked in _ALWAYS_BLOCKED):
        raise ValueError('Loopback, multicast, link-local, and reserved ranges cannot be scanned.')

    if network.is_private and not settings.lab_mode:
        raise ValueError('Private network ranges are allowed only when LAB_MODE is enabled.')

    return network


def classify_target(raw: str) -> dict:
    try:
        network = ipaddress.ip_network(raw, strict=True)
    except ValueError:
        network = None

    if network is not None:
        return {'type': 'cidr', 'original': raw}

    has_scheme = '://' in raw
    if has_scheme and not raw.lower().startswith(('http://', 'https://')):
        raise ValueError('Not a valid IP range or URL')

    scheme = 'https'
    if raw.lower().startswith('http://'):
        scheme = 'http'
        url = raw
    elif raw.lower().startswith('https://'):
        url = raw
    else:
        url = f'//{raw}'

    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        parsed.port
    except ValueError as exc:
        raise ValueError('Not a valid IP range or URL') from exc

    if (
        not hostname
        or parsed.username is not None
        or parsed.password is not None
        or not _HOSTNAME_PATTERN.fullmatch(hostname)
    ):
        raise ValueError('Not a valid IP range or URL')

    try:
        resolved_ip = ipaddress.ip_address(socket.gethostbyname(hostname))
    except (OSError, ValueError) as exc:
        raise ValueError('Could not resolve hostname') from exc

    if any(
        resolved_ip.version == blocked.version and resolved_ip in blocked
        for blocked in _ALWAYS_BLOCKED
    ):
        raise ValueError('Loopback, multicast, link-local, and reserved ranges cannot be scanned.')

    if resolved_ip.is_private and not settings.lab_mode:
        raise ValueError('Private network ranges are allowed only when LAB_MODE is enabled.')

    return {
        'type': 'url',
        'original': raw,
        'hostname': hostname,
        'resolved_ip': str(resolved_ip),
        'scheme': scheme,
    }