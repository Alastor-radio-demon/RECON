from collections import Counter
from html import escape
from io import BytesIO
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.models import Host, Scan


SEVERITIES = ('critical', 'high', 'medium', 'low')
SEVERITY_COLORS = {
    'critical': colors.HexColor('#a5262f'),
    'high': colors.HexColor('#cc5a20'),
    'medium': colors.HexColor('#b88716'),
    'low': colors.HexColor('#347a62'),
    'unrated': colors.HexColor('#536475'),
}
TABLE_HEADER = colors.HexColor('#183b4e')


def _text(value: Any) -> str:
    return escape(str(value)).replace('\n', '<br/>')


def _paragraph(value: Any, style: ParagraphStyle) -> Paragraph:
    return Paragraph(_text(value), style)


def _severity(value: str | None) -> str:
    normalized = (value or '').strip().lower()
    return normalized if normalized in SEVERITIES else 'unrated'


def _finding_counts(hosts: list[Host]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for host in hosts:
        for port in host.ports:
            counts.update(_severity(cve.severity) for cve in port.cves)
        counts.update(_severity(finding.severity) for finding in host.web_findings)
        counts.update('unrated' for _ in host.vuln_findings)
    return counts


def _make_table(rows: list[list[Any]], widths: list[float], header: bool = True) -> Table:
    table = Table(rows, colWidths=widths, repeatRows=1 if header else 0, hAlign='LEFT', splitByRow=1)
    rules = [
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('GRID', (0, 0), (-1, -1), 0.35, colors.HexColor('#cbd5dc')),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
    ]
    if header:
        rules.extend([
            ('BACKGROUND', (0, 0), (-1, 0), TABLE_HEADER),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ])
    table.setStyle(TableStyle(rules))
    return table


def _severity_badge(value: str, styles: dict[str, ParagraphStyle]) -> Table:
    normalized = _severity(value)
    badge = Table([[_paragraph(normalized.upper(), styles['badge'])]], colWidths=[0.76 * inch])
    badge.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), SEVERITY_COLORS[normalized]),
        ('BOX', (0, 0), (-1, -1), 0, SEVERITY_COLORS[normalized]),
        ('LEFTPADDING', (0, 0), (-1, -1), 3),
        ('RIGHTPADDING', (0, 0), (-1, -1), 3),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    return badge


def _recommendations(host: Host) -> list[str]:
    ordered: list[tuple[int, str]] = []
    for port in host.ports:
        service = port.service or 'service'
        for cve in port.cves:
            severity = _severity(cve.severity)
            rank = SEVERITIES.index(severity) if severity in SEVERITIES else len(SEVERITIES)
            ordered.append((rank, f'Update {service} on port {port.port} to address {cve.cve_id} (CVSS {cve.cvss if cve.cvss is not None else "N/A"}).'))
    for finding in host.web_findings:
        severity = _severity(finding.severity)
        rank = SEVERITIES.index(severity) if severity in SEVERITIES else len(SEVERITIES)
        ordered.append((rank, f'Remediate the {severity} web finding {finding.name} ({finding.template_id}) at {finding.matched_at}.'))
    for finding in host.vuln_findings:
        if finding.state.upper() == 'VULNERABLE':
            location = f' on port {finding.port}' if finding.port is not None else ''
            cves = f' ({", ".join(finding.cve_ids)})' if finding.cve_ids else ''
            ordered.append((1, f'Investigate and remediate the confirmed NSE finding {finding.script_id}{location}{cves}.'))
    return [text for _, text in sorted(ordered, key=lambda item: item[0])]


def _host_findings(host: Host, story: list[Any], styles: dict[str, ParagraphStyle], width: float) -> None:
    cves = [(port, cve) for port in host.ports for cve in port.cves]
    if cves:
        story.append(Paragraph('CVE findings', styles['subheading']))
        rows = [[
            _paragraph('Severity', styles['table_header']),
            _paragraph('CVE', styles['table_header']),
            _paragraph('Description', styles['table_header']),
            _paragraph('CVSS', styles['table_header']),
            _paragraph('Port', styles['table_header']),
        ]]
        for port, cve in cves:
            rows.append([
                _severity_badge(cve.severity, styles),
                _paragraph(cve.cve_id, styles['body']),
                _paragraph(cve.description or 'No description available.', styles['body']),
                _paragraph(cve.cvss if cve.cvss is not None else 'N/A', styles['body']),
                _paragraph(f'{port.port}/{port.protocol}', styles['body']),
            ])
        story.append(_make_table(rows, [0.9 * inch, 1.0 * inch, width - 4.0 * inch, 0.55 * inch, 0.85 * inch]))
        story.append(Spacer(1, 8))

    if host.vuln_findings:
        story.append(Paragraph('NSE vulnerability findings', styles['subheading']))
        rows = [[
            _paragraph('State', styles['table_header']),
            _paragraph('Script', styles['table_header']),
            _paragraph('Port', styles['table_header']),
            _paragraph('Finding details', styles['table_header']),
        ]]
        rows.extend([
            [
                _paragraph(finding.state, styles['body']),
                _paragraph(finding.script_id, styles['body']),
                _paragraph(finding.port if finding.port is not None else 'Host', styles['body']),
                _paragraph(finding.output, styles['body']),
            ]
            for finding in host.vuln_findings
        ])
        story.append(_make_table(rows, [0.8 * inch, 1.15 * inch, 0.55 * inch, width - 2.5 * inch]))
        story.append(Spacer(1, 8))

    if host.web_findings:
        story.append(Paragraph('Nuclei web findings', styles['subheading']))
        rows = [[
            _paragraph('Severity', styles['table_header']),
            _paragraph('Finding', styles['table_header']),
            _paragraph('Description / matched URL', styles['table_header']),
        ]]
        rows.extend([
            [
                _severity_badge(finding.severity, styles),
                _paragraph(f'{finding.name} ({finding.template_id})', styles['body']),
                _paragraph(f'{finding.description or "No description available."}\n{finding.matched_at}', styles['body']),
            ]
            for finding in host.web_findings
        ])
        story.append(_make_table(rows, [1.0 * inch, 2.15 * inch, width - 3.15 * inch]))
        story.append(Spacer(1, 8))


def build_report(scan: Scan) -> bytes:
    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=0.65 * inch,
        leftMargin=0.65 * inch,
        topMargin=0.65 * inch,
        bottomMargin=0.65 * inch,
        title=f'RECON scan report {scan.id}',
        author='RECON',
    )
    base_styles = getSampleStyleSheet()
    styles = {
        'title': ParagraphStyle('ReportTitle', parent=base_styles['Title'], textColor=TABLE_HEADER, fontSize=25, leading=30, alignment=TA_CENTER, spaceAfter=16),
        'heading': ParagraphStyle('ReportHeading', parent=base_styles['Heading1'], textColor=TABLE_HEADER, fontSize=17, leading=21, spaceBefore=8, spaceAfter=10),
        'subheading': ParagraphStyle('ReportSubheading', parent=base_styles['Heading2'], textColor=TABLE_HEADER, fontSize=12, leading=15, spaceBefore=10, spaceAfter=6),
        'body': ParagraphStyle('ReportBody', parent=base_styles['BodyText'], fontSize=8.5, leading=11, wordWrap='CJK'),
        'table_header': ParagraphStyle('ReportTableHeader', parent=base_styles['BodyText'], textColor=colors.white, fontSize=8, leading=10),
        'badge': ParagraphStyle('SeverityBadge', parent=base_styles['BodyText'], textColor=colors.white, fontSize=7, leading=9, alignment=TA_CENTER),
        'disclaimer': ParagraphStyle('Disclaimer', parent=base_styles['BodyText'], fontSize=8, leading=11, textColor=colors.HexColor('#45545f'), spaceBefore=22),
    }
    story: list[Any] = [
        Spacer(1, 1.1 * inch),
        Paragraph('RECON SCAN REPORT', styles['title']),
        Paragraph(_text(scan.original_target or scan.cidr), ParagraphStyle('CoverTarget', parent=styles['heading'], alignment=TA_CENTER)),
        Spacer(1, 0.2 * inch),
    ]
    cover_rows = [
        [_paragraph('Scan date', styles['body']), _paragraph(scan.created_at.strftime('%Y-%m-%d %H:%M UTC'), styles['body'])],
        [_paragraph('Scope', styles['body']), _paragraph(f'{scan.target_type.upper()} - {scan.cidr}', styles['body'])],
        [_paragraph('Scan depth', styles['body']), _paragraph(scan.depth.title(), styles['body'])],
        [_paragraph('Overall grade', styles['body']), _paragraph(scan.network_grade or 'Not available', styles['body'])],
    ]
    cover_table = _make_table(cover_rows, [1.45 * inch, 4.5 * inch], header=False)
    story.extend([cover_table, Paragraph(
        'This report contains security findings from an authorized scan. Scan only systems for which you have explicit permission; unauthorized scanning is prohibited.',
        styles['disclaimer'],
    ), PageBreak()])

    width = document.width
    hosts = scan.hosts
    counts = _finding_counts(hosts)
    total_findings = sum(counts.values())
    total_ports = sum(len(host.ports) for host in hosts)
    urgent_count = counts['critical'] + counts['high']
    if not hosts:
        narrative = 'No hosts were discovered within the requested scope; no host-level findings are available.'
    elif urgent_count:
        narrative = f'The scan identified {urgent_count} critical or high-severity finding(s) that should be prioritized for remediation.'
    else:
        narrative = 'No critical or high-severity findings were identified; review the remaining findings and maintain routine patching.'

    story.extend([
        Paragraph('Executive summary', styles['heading']),
        _paragraph(f'{len(hosts)} hosts - {total_ports} open ports - {total_findings} findings', styles['body']),
        Spacer(1, 6),
        _paragraph(narrative, styles['body']),
        Paragraph('Findings by severity', styles['subheading']),
    ])
    severity_rows = [[_paragraph('Severity', styles['table_header']), _paragraph('Count', styles['table_header'])]]
    severity_rows.extend([
        [_paragraph(severity.title(), styles['body']), _paragraph(counts[severity], styles['body'])]
        for severity in (*SEVERITIES, 'unrated')
    ])
    story.append(_make_table(severity_rows, [width - 1.0 * inch, 1.0 * inch]))
    story.extend([
        Paragraph('Methodology', styles['subheading']),
        _paragraph(
            'This report summarizes the scan outputs available at completion: discovered open ports, CVE enrichment for detected services, Nmap NSE vulnerability scripts, and Nuclei web templates when available. Findings are point-in-time observations and should be validated before remediation.',
            styles['body'],
        ),
    ])

    if not hosts:
        story.extend([Spacer(1, 14), _paragraph('No hosts were discovered for this scan.', styles['body'])])
    for host in hosts:
        story.append(PageBreak())
        label = host.hostname or host.ip
        if host.hostname and host.hostname != host.ip:
            label = f'{host.ip} ({host.hostname})'
        story.append(Paragraph(_text(label), styles['heading']))
        operating_system = getattr(host, 'os', None)
        story.append(_paragraph(
            f'OS: {operating_system or "Unknown"} - Score: {host.score if host.score is not None else "N/A"} - Grade: {host.grade or "N/A"}',
            styles['body'],
        ))
        story.append(Paragraph('Open ports', styles['subheading']))
        port_rows = [[
            _paragraph('Port / protocol', styles['table_header']),
            _paragraph('Service', styles['table_header']),
            _paragraph('Product / version', styles['table_header']),
        ]]
        if host.ports:
            port_rows.extend([
                [
                    _paragraph(f'{port.port}/{port.protocol}', styles['body']),
                    _paragraph(port.service, styles['body']),
                    _paragraph(' '.join(value for value in (port.product, port.version) if value) or 'Not identified', styles['body']),
                ]
                for port in host.ports
            ])
        else:
            port_rows.append([_paragraph('No open ports reported.', styles['body']), '', ''])
        story.append(_make_table(port_rows, [1.25 * inch, 1.6 * inch, width - 2.85 * inch]))
        story.append(Spacer(1, 8))

        _host_findings(host, story, styles, width)
        if not (host.vuln_findings or host.web_findings or any(port.cves for port in host.ports)):
            story.append(_paragraph('No known vulnerabilities found.', styles['body']))

        story.append(Paragraph('Risk factors', styles['subheading']))
        if host.risk_reasons:
            story.extend([Paragraph(_text(reason), styles['body'], bulletText='-') for reason in host.risk_reasons])
        else:
            story.append(_paragraph('No risk factors reported.', styles['body']))

        story.append(Paragraph('Recommended remediation', styles['subheading']))
        recommendations = _recommendations(host)
        if recommendations:
            story.extend([_paragraph(f'{number}. {recommendation}', styles['body']) for number, recommendation in enumerate(recommendations, 1)])
        else:
            story.append(_paragraph('Nothing to fix. Keep systems patched and re-scan after changes.', styles['body']))

    document.build(story)
    return buffer.getvalue()