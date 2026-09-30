import pytest

from app.scanner.vulnscan import parse_vulnscan_xml


NMAP_XML = '''<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="445">
        <state state="open" />
        <script id="smb-vuln-ms17-010" output="&#10;  VULNERABLE: Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)&#10;  State: VULNERABLE&#10;  IDs:  CVE:CVE-2017-0144&#10;" />
        <script id="smb-os-discovery" output="Windows Server" />
      </port>
    </ports>
    <hostscript>
      <script id="smb-vuln-conficker" output="NOT VULNERABLE" />
    </hostscript>
  </host>
</nmaprun>
'''


def test_parse_vulnscan_xml_extracts_vulnerable_finding_and_cves() -> None:
    assert parse_vulnscan_xml(NMAP_XML) == [
        {
            'script_id': 'smb-vuln-ms17-010',
            'port': 445,
            'output': '\n  VULNERABLE: Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)\n  State: VULNERABLE\n  IDs:  CVE:CVE-2017-0144\n',
            'cve_ids': ['CVE-2017-0144'],
            'state': 'VULNERABLE',
        },
        {
            'script_id': 'smb-vuln-conficker',
            'port': None,
            'output': 'NOT VULNERABLE',
            'cve_ids': [],
          'state': 'INFO',
        },
    ]


def test_parse_vulnscan_xml_raises_for_invalid_xml() -> None:
    with pytest.raises(RuntimeError, match='invalid XML'):
        parse_vulnscan_xml('<nmaprun>')