from app.scanner import webscan
from app.scanner.webscan import parse_nuclei_jsonl


NUCLEI_JSONL = '''
{"template-id":"wordpress-plugin-cve","info":{"name":"Vulnerable WordPress Plugin","severity":"critical","description":"A plugin vulnerability affects versions below 2.0.","reference":["https://example.test/advisory"],"classification":{"cve-id":["CVE-2024-12345"]}},"matched-at":"http://192.0.2.10:8080/wp-content/plugins/example/"}
this is not valid JSON
{"template-id":"generic-exposure","info":{"name":"Exposed backup file CVE-2023-54321","severity":"medium","reference":"https://example.test/template"},"matched-at":"https://192.0.2.10:8443/backup.zip"}
'''


def test_parse_nuclei_jsonl_extracts_findings_and_skips_malformed_lines() -> None:
    assert parse_nuclei_jsonl(NUCLEI_JSONL) == [
        {
            'template_id': 'wordpress-plugin-cve',
            'name': 'Vulnerable WordPress Plugin',
            'severity': 'critical',
            'description': 'A plugin vulnerability affects versions below 2.0.',
            'matched_at': 'http://192.0.2.10:8080/wp-content/plugins/example/',
            'reference': ['https://example.test/advisory'],
            'cve_ids': ['CVE-2024-12345'],
        },
        {
            'template_id': 'generic-exposure',
            'name': 'Exposed backup file CVE-2023-54321',
            'severity': 'medium',
            'description': None,
            'matched_at': 'https://192.0.2.10:8443/backup.zip',
            'reference': ['https://example.test/template'],
            'cve_ids': ['CVE-2023-54321'],
        },
    ]


def test_run_nuclei_skips_when_binary_is_missing_and_warns_once(
    monkeypatch,
    caplog,
) -> None:
    monkeypatch.setattr(webscan, '_missing_nuclei_warned', False)

    def missing_binary(*args, **kwargs):
        raise FileNotFoundError

    monkeypatch.setattr(webscan.subprocess, 'run', missing_binary)

    assert webscan.run_nuclei('http://192.0.2.10:80') == []
    assert webscan.run_nuclei('http://192.0.2.11:80') == []
    assert caplog.text.count('Nuclei was not found on PATH') == 1


def test_run_nuclei_sets_concurrency_and_rate_limit(monkeypatch) -> None:
    commands: list[list[str]] = []

    class CompletedProcess:
        stdout = ''

    def fake_run(command, **kwargs):
        commands.append(command)
        return CompletedProcess()

    monkeypatch.setattr(webscan.subprocess, 'run', fake_run)

    assert webscan.run_nuclei('http://192.0.2.10:80') == []
    assert commands[0][commands[0].index('-c') + 1] == '25'
    assert commands[0][commands[0].index('-rl') + 1] == '150'