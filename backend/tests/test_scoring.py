from app.models import Host, Port
from app.scanner.scoring import score_host, score_network


def make_host(*port_numbers: int) -> Host:
    return Host(
        ip='192.168.1.10',
        ports=[Port(port=number, protocol='tcp', service='unknown') for number in port_numbers],
    )


def test_clean_host_scores_near_100() -> None:
    score, grade, reasons = score_host(make_host())

    assert score == 100
    assert grade == 'A'
    assert reasons == []


def test_telnet_rdp_and_smb_reduce_score_to_f() -> None:
    score, grade, reasons = score_host(make_host(23, 3389, 445))

    assert score == 45
    assert grade == 'F'
    assert reasons == [
        'Telnet exposed - cleartext (port 23): -25',
        'RDP exposed (port 3389): -15',
        'SMB exposed (port 445): -15',
    ]


def test_many_open_ports_add_surface_penalty() -> None:
    score, grade, reasons = score_host(make_host(1000, 1001, 1002, 1003, 1004))

    assert score == 94
    assert grade == 'A'
    assert reasons == ['5 open ports: -6']


def test_host_score_is_floored_at_zero() -> None:
    score, grade, _ = score_host(make_host(21, 23, 25, 69, 110, 139, 161, 445, 1433, 3389))

    assert score == 0
    assert grade == 'F'


def test_score_network_averages_host_scores_and_assigns_grade() -> None:
    score, grade = score_network([make_host(), make_host(23, 3389, 445), make_host(1000, 1001, 1002, 1003, 1004)])

    assert score == 80
    assert grade == 'B'


def test_empty_network_has_zero_score() -> None:
    assert score_network([]) == (0, 'F')