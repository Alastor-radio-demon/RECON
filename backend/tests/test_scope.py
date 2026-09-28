import pytest

from app import config
from app.scope import validate_cidr


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