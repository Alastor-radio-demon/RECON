export const gobusterFindings = [
  { path: '/index.html', status: 200, note: 'Reachable page' },
  { path: '/.hta', status: 403, note: 'Blocked, but present' },
  { path: '/.htpasswd', status: 403, note: 'Blocked, but present' },
  { path: '/.htaccess', status: 403, note: 'Blocked, but present' },
  { path: '/server-status', status: 403, note: 'Blocked, but present' },
] as const;
