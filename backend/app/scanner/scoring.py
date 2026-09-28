from app.models import Host


RISKY_PORTS: dict[int, tuple[int, str]] = {
    21: (15, 'FTP exposed'),
    23: (25, 'Telnet exposed - cleartext'),
    25: (10, 'SMTP exposed'),
    53: (5, 'DNS exposed'),
    69: (20, 'TFTP exposed - no auth'),
    110: (10, 'POP3 exposed - often cleartext'),
    111: (10, 'RPC portmapper exposed'),
    135: (10, 'MS RPC exposed'),
    139: (15, 'NetBIOS exposed'),
    143: (10, 'IMAP exposed - often cleartext'),
    161: (15, 'SNMP exposed'),
    389: (10, 'LDAP exposed'),
    445: (15, 'SMB exposed'),
    512: (15, 'rexec exposed - cleartext'),
    513: (15, 'rlogin exposed - cleartext'),
    514: (15, 'rsh exposed - cleartext'),
    1433: (15, 'MSSQL exposed'),
    1521: (15, 'Oracle DB exposed'),
    2049: (10, 'NFS exposed'),
    3306: (10, 'MySQL exposed'),
    3389: (15, 'RDP exposed'),
    5432: (10, 'PostgreSQL exposed'),
    5900: (15, 'VNC exposed'),
    5985: (10, 'WinRM exposed'),
    6379: (15, 'Redis exposed - often unauthenticated'),
    8080: (5, 'Alt HTTP exposed - check for admin panel'),
    8443: (5, 'Alt HTTPS exposed - check for admin panel'),
    9200: (15, 'Elasticsearch exposed - often unauthenticated'),
    11211: (15, 'Memcached exposed - often unauthenticated'),
    27017: (15, 'MongoDB exposed - often unauthenticated'),
    22: (5, 'SSH exposed'),
    80: (5, 'Unencrypted HTTP'),
}


def _grade_for_score(score: int) -> str:
    if score >= 90:
        return 'A'
    if score >= 80:
        return 'B'
    if score >= 70:
        return 'C'
    if score >= 55:
        return 'D'
    return 'F'


def score_host(host: Host) -> tuple[int, str, list[str]]:
    score = 100
    reasons: list[str] = []

    for port in host.ports:
        risk = RISKY_PORTS.get(port.port)
        if risk is not None:
            weight, label = risk
            score -= weight
            reasons.append(f'{label} (port {port.port}): -{weight}')

    extra_port_count = max(0, len(host.ports) - 3)
    if extra_port_count:
        surface_penalty = extra_port_count * 3
        score -= surface_penalty
        reasons.append(f'{len(host.ports)} open ports: -{surface_penalty}')

    score = max(0, score)
    return score, _grade_for_score(score), reasons


def score_network(hosts: list[Host]) -> tuple[int, str]:
    if not hosts:
        return 0, _grade_for_score(0)

    host_scores = [score_host(host)[0] for host in hosts]
    network_score = round(sum(host_scores) / len(host_scores))
    return network_score, _grade_for_score(network_score)