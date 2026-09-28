import pytest

from app.scanner.portscan import parse_portscan_xml


NMAP_XML = '''<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack" />
        <service name="ssh" product="OpenSSH" version="9.6" />
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack" />
        <service name="http" product="nginx" version="1.24.0" />
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed" reason="reset" />
        <service name="https" />
      </port>
    </ports>
  </host>
</nmaprun>
'''


def test_parse_portscan_xml_returns_only_open_ports_with_service_details() -> None:
    assert parse_portscan_xml(NMAP_XML) == {
        'ports': [
            {
                'port': 22,
                'protocol': 'tcp',
                'state': 'open',
                'service': 'ssh',
                'product': 'OpenSSH',
                'version': '9.6',
            },
            {
                'port': 80,
                'protocol': 'tcp',
                'state': 'open',
                'service': 'http',
                'product': 'nginx',
                'version': '1.24.0',
            },
        ]
    }


def test_parse_portscan_xml_raises_for_invalid_xml() -> None:
    with pytest.raises(RuntimeError, match='invalid XML'):
        parse_portscan_xml('<nmaprun>')