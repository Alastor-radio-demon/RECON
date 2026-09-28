from app.scanner.discovery import parse_discovery_xml


NMAP_XML = '''<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up" reason="arp-response" />
    <address addr="192.168.1.10" addrtype="ipv4" />
    <hostnames>
      <hostname name="workstation.local" type="PTR" />
    </hostnames>
  </host>
  <host>
    <status state="down" reason="no-response" />
    <address addr="192.168.1.11" addrtype="ipv4" />
  </host>
  <host>
    <status state="up" reason="arp-response" />
    <address addr="192.168.1.12" addrtype="ipv4" />
  </host>
</nmaprun>
'''


def test_parse_discovery_xml_returns_up_hosts_and_optional_hostnames() -> None:
    assert parse_discovery_xml(NMAP_XML) == [
        {'ip': '192.168.1.10', 'hostname': 'workstation.local'},
        {'ip': '192.168.1.12', 'hostname': None},
    ]