export type Severity = 'critical' | 'high' | 'medium' | 'low';

export interface Finding {
  id: string;
  sev: Severity;
  cvss: number;
  title: string;
  port: number;
  fix: string;
  kev?: boolean;
}

export interface Port {
  port: number;
  proto: 'tcp';
  service: string;
  product: string;
}

export interface Host {
  n: number;
  name: string;
  os: string;
  score: number;
  ports: Port[];
  vulns: Finding[];
}

export const SEV: Severity[] = ['critical', 'high', 'medium', 'low'];
export const SEVC: Record<Severity, string> = {
  critical: 'var(--crit)',
  high: 'var(--high)',
  medium: 'var(--med)',
  low: 'var(--low)',
};
export const GC: Record<'A' | 'B' | 'C' | 'D' | 'F', string> = {
  A: 'var(--gA)',
  B: 'var(--gB)',
  C: 'var(--gC)',
  D: 'var(--gD)',
  F: 'var(--gF)',
};

export const grade = (score: number): 'A' | 'B' | 'C' | 'D' | 'F' =>
  score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : score >= 55 ? 'D' : 'F';

export const esc = (input: string): string =>
  String(input).replace(/[&<>"']/g, (char) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  }[char] ?? char));

const V = (id: string, sev: Severity, cvss: number, title: string, port: number, fix: string, kev = false): Finding => ({
  id,
  sev,
  cvss,
  title,
  port,
  fix,
  kev,
});

const H = (n: number, name: string, os: string, score: number, ports: Array<[number, string, string]>, vulns: Finding[]): Host => ({
  n,
  name,
  os,
  score,
  ports: ports.map(([port, service, product]) => ({ port, proto: 'tcp', service, product })),
  vulns,
});

export const HOSTS: Host[] = [
  H(1,'gateway.lan','MikroTik RouterOS 6.x',58,[[22,'ssh','OpenSSH 7.4'],[53,'domain','dnsmasq 2.80'],[80,'http','nginx 1.14.0'],[8291,'winbox','MikroTik Winbox']],[
    V('CVE-2018-15473','medium',5.3,'OpenSSH username enumeration',22,'Upgrade OpenSSH and restrict SSH to a management VLAN.'),
    V('EXPOSED-ADMIN','high',7.5,'Winbox admin port reachable from the whole LAN',8291,'Limit Winbox to an admin address list or disable it.')]),
  H(10,'fileserver.lan','Ubuntu 16.04',32,[[21,'ftp','vsftpd 2.3.4'],[22,'ssh','OpenSSH 7.2p2'],[139,'netbios-ssn','Samba smbd 3.X'],[445,'microsoft-ds','Samba 4.3.11']],[
    V('CVE-2011-2523','critical',10,'vsftpd 2.3.4 backdoor command execution',21,'Remove vsftpd 2.3.4 and install a maintained FTP or SFTP service.',true),
    V('CVE-2017-7494','critical',9.8,'Samba remote code execution (SambaCry)',445,'Upgrade Samba to a patched release.',true),
    V('CVE-2016-6210','medium',5.9,'OpenSSH user enumeration via timing',22,'Upgrade OpenSSH; move this OS off end-of-life.')]),
  H(12,'printer-2f.lan','HP JetDirect embedded',71,[[80,'http','HP embedded web server'],[631,'ipp','CUPS 2.2'],[9100,'jetdirect','HP JetDirect']],[
    V('CVE-2017-2741','high',8.4,'PJL remote code execution on print port',9100,'Update firmware and block port 9100 except from the print server.')]),
  H(20,'web01.lan','Ubuntu 22.04',74,[[22,'ssh','OpenSSH 8.9p1'],[80,'http','nginx 1.18.0'],[443,'https','nginx 1.18.0']],[
    V('CVE-2021-23017','high',7.7,'nginx resolver off-by-one',80,'Upgrade nginx to 1.20.1 or later.'),
    V('TLS-WEAK-PROTO','medium',5,'TLS 1.0 and 1.1 still enabled',443,'Allow TLS 1.2 and 1.3 only.')]),
  H(21,'db01.lan','Debian 11',66,[[22,'ssh','OpenSSH 8.4p1'],[3306,'mysql','MySQL 5.7.30']],[
    V('EXPOSED-DB','high',7.5,'MySQL reachable from the whole subnet',3306,'Bind MySQL to the app server only and add firewall rules.'),
    V('CVE-2020-14812','medium',4.9,'MySQL server locking component denial of service',3306,'Upgrade MySQL to the latest 5.7 patch or 8.x.')]),
  H(34,'dc01.corp','Windows Server 2016',45,[[53,'domain','Simple DNS Plus'],[88,'kerberos-sec','Microsoft Kerberos'],[135,'msrpc','Microsoft RPC'],[389,'ldap','Active Directory LDAP'],[445,'microsoft-ds','SMB'],[3389,'ms-wbt-server','Microsoft RDP']],[
    V('CVE-2020-1472','critical',10,'Netlogon elevation of privilege (Zerologon)',445,'Install the August 2020 or later cumulative update and enforce secure RPC.',true),
    V('SMB-SIGNING','medium',5.3,'SMB signing not required',445,'Require SMB signing through Group Policy.'),
    V('RDP-EXPOSED','medium',5,'RDP open to all workstations',3389,'Restrict RDP to a jump host and require NLA.')]),
  H(50,'nas.lan','Synology DSM 7',83,[[22,'ssh','OpenSSH 8.2'],[80,'http','nginx'],[443,'https','nginx'],[5000,'http','Synology DSM']],[
    V('TLS-CERT-EXPIRED','medium',4.3,'TLS certificate expired 41 days ago',443,'Renew the certificate and enable auto-renewal.')]),
  H(51,'cam-lobby.lan','Embedded Linux (BusyBox)',28,[[23,'telnet','BusyBox telnetd'],[80,'http','GoAhead-Webs 2.5'],[554,'rtsp','RTSP stream']],[
    V('CVE-2017-17562','critical',9.8,'GoAhead web server remote code execution',80,'Update camera firmware or replace the device.'),
    V('WEAK-CREDS','high',8.8,'Telnet accepts a default credential pair',23,'Change default credentials and disable Telnet.'),
    V('CLEARTEXT-TELNET','high',7.5,'Telnet transmits credentials in cleartext',23,'Disable Telnet; use SSH if remote access is needed.')]),
  H(77,'dev-laptop.lan','macOS 14',91,[[7000,'afs3-fileserver','AirPlay receiver']],[]),
  H(100,'pi-hole.lan','Debian 12',88,[[22,'ssh','OpenSSH 9.2p1'],[53,'domain','dnsmasq 2.89'],[80,'http','lighttpd 1.4.69']],[
    V('HTTP-NO-TLS','low',3.7,'Admin interface served over HTTP',80,'Serve the admin page over HTTPS only.')]),
  H(101,'hass.lan','Linux (Home Assistant OS)',79,[[22,'ssh','OpenSSH 9.1'],[8123,'http','Home Assistant']],[
    V('HTTP-NO-TLS','low',3.7,'Web UI served over HTTP',8123,'Put the UI behind a TLS reverse proxy.')]),
  H(130,'win-ws04.corp','Windows 10',62,[[135,'msrpc','Microsoft RPC'],[445,'microsoft-ds','SMB'],[3389,'ms-wbt-server','Microsoft RDP']],[
    V('RDP-EXPOSED','high',7,'RDP reachable without network-level authentication',3389,'Enable NLA and restrict RDP to a jump host.'),
    V('SMB-SIGNING','medium',5.3,'SMB signing not required',445,'Require SMB signing through Group Policy.')]),
  H(200,'jenkins.lan','Ubuntu 20.04',40,[[22,'ssh','OpenSSH 8.2p1'],[8080,'http','Jetty 9.4 (Jenkins 2.319)']],[
    V('CVE-2024-23897','critical',9.8,'Jenkins CLI arbitrary file read',8080,'Upgrade Jenkins to a fixed LTS release and disable the CLI if unused.',true),
    V('EXPOSED-ADMIN','high',7.5,'CI server open to the whole LAN',8080,'Place behind a VPN or reverse proxy with SSO.')]),
  H(210,'voip.lan','Linux',69,[[22,'ssh','OpenSSH 7.9p1'],[5060,'sip','Asterisk 16.2']],[
    V('SIP-EXPOSED','medium',5,'SIP service open to the whole LAN',5060,'Restrict SIP to known phone addresses.')]),
];

export const HISTORY = [
  {when:'Today, 09:12',cidr:'192.168.1.0/24',hosts:14,find:22,g:'D',dur:'6m 41s'},
  {when:'Yesterday, 17:40',cidr:'192.168.1.0/24',hosts:13,find:25,g:'D',dur:'6m 12s'},
  {when:'Mon, 14:05',cidr:'10.10.0.0/24',hosts:31,find:40,g:'F',dur:'11m 03s'},
  {when:'Last week',cidr:'192.168.1.0/24',hosts:12,find:28,g:'D',dur:'5m 58s'},
] as const;
