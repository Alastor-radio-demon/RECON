import pytest

from app import config
from app.scope import classify_target, validate_cidr


def test_accepts_private_cidr_when_lab_mode_is_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config.settings, 'lab_mode', True)

    network = validate_cidr('192.168.1.0/24', authorized=True)

    assert str(network) == '192.168.1.0/24'


def test_rejects_private_cidr_when_lab_mode_is_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config.settings, 'lab_mode', False)

    with pytest.raises(ValueError, match='LAB_MODE'):
        validate_cidr('192.168.1.0/24', authorized=True)


def test_rejects_prefix_shorter_than_max_prefix() -> None:
    with pytest.raises(ValueError, match='prefix length'):
        validate_cidr('192.168.0.0/16', authorized=True)


@pytest.mark.parametrize('cidr', ['127.0.0.0/24', '224.0.0.0/24'])
def test_rejects_loopback_and_multicast(cidr: str) -> None:
    with pytest.raises(ValueError, match='Loopback, multicast'):
        validate_cidr(cidr, authorized=True)


def test_rejects_unauthorized_scope() -> None:
    with pytest.raises(ValueError, match='authorized'):
        validate_cidr('8.8.8.0/24', authorized=False)


def test_accepts_public_cidr() -> None:
    network = validate_cidr('8.8.8.0/24', authorized=True)

    assert str(network) == '8.8.8.0/24'


def test_classifies_public_https_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr('app.scope.socket.gethostbyname', lambda _: '8.8.8.8')

    target = classify_target('https://example.com/page?x=1')

    assert target == {
        'type': 'url',
        'original': 'https://example.com/page?x=1',
        'hostname': 'example.com',
        'resolved_ip': '8.8.8.8',
        'scheme': 'https',
    }


def test_classifies_bare_domain_as_https(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr('app.scope.socket.gethostbyname', lambda _: '8.8.8.8')

    target = classify_target('example.com')

    assert target['hostname'] == 'example.com'
    assert target['scheme'] == 'https'


def test_rejects_private_url_outside_lab_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config.settings, 'lab_mode', False)
    monkeypatch.setattr('app.scope.socket.gethostbyname', lambda _: '192.168.1.10')

    with pytest.raises(ValueError, match='LAB_MODE'):
        classify_target('http://example.com')


def test_allows_private_url_in_lab_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config.settings, 'lab_mode', True)
    monkeypatch.setattr('app.scope.socket.gethostbyname', lambda _: '192.168.1.10')

    target = classify_target('http://example.com')

    assert target['resolved_ip'] == '192.168.1.10'


def test_rejects_unresolvable_hostname(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_resolution_error(_: str) -> str:
        raise OSError('name resolution failed')

    monkeypatch.setattr('app.scope.socket.gethostbyname', raise_resolution_error)

    with pytest.raises(ValueError, match='Could not resolve hostname'):
        classify_target('example.com')


def test_rejects_input_that_is_not_a_cidr_or_hostname() -> None:
    with pytest.raises(ValueError, match='Not a valid IP range or URL'):
        classify_target('not a domain')