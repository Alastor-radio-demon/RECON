export type ScanStatus = 'pending' | 'discovering' | 'completed' | 'failed';
export type HostStatus = 'pending' | 'scanning' | 'done';

export interface CVE {
  cve_id: string;
  description: string;
  cvss: number | null;
  severity: string;
}

export interface Port {
  port: number;
  protocol: string;
  service: string;
  product: string | null;
  version: string | null;
  cves: CVE[];
}

export interface Host {
  ip: string;
  hostname: string | null;
  status: HostStatus;
  ports: Port[];
  score: number | null;
  grade: string | null;
  risk_reasons: string[];
}

export interface Scan {
  id: string;
  cidr: string;
  status: ScanStatus;
  created_at: string;
  hosts: Host[];
  error: string | null;
  network_score: number | null;
  network_grade: string | null;
}

declare global {
  interface ImportMetaEnv {
    readonly VITE_API_URL?: string;
  }

  interface ImportMeta {
    readonly env: ImportMetaEnv;
  }
}

const API_BASE_URL = (import.meta.env.VITE_API_URL || 'http://localhost:8000').replace(/\/+$/, '');

async function responseError(response: Response): Promise<Error> {
  try {
    const body: unknown = await response.json();
    if (body && typeof body === 'object') {
      const payload = body as { detail?: unknown; message?: unknown; error?: unknown };
      const message = payload.detail ?? payload.message ?? payload.error;
      if (typeof message === 'string') return new Error(message);
      if (message !== undefined) return new Error(JSON.stringify(message));
    }
  } catch {
    // Use the generic status message when the response has no JSON body.
  }

  return new Error(`Request failed (${response.status})`);
}

export async function createScan(cidr: string, authorized: boolean): Promise<Scan> {
  const response = await fetch(`${API_BASE_URL}/scans`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ cidr, authorized }),
  });

  if (!response.ok) {
    if (response.status === 400) throw await responseError(response);
    throw new Error('Request failed');
  }

  return response.json() as Promise<Scan>;
}

export async function getScan(id: string): Promise<Scan> {
  const response = await fetch(`${API_BASE_URL}/scans/${encodeURIComponent(id)}`);

  if (!response.ok) {
    if (response.status === 404) throw new Error('Scan not found');
    throw new Error('Request failed');
  }

  return response.json() as Promise<Scan>;
}

