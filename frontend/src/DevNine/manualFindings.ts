export const manualFindings = [
  {
    title: 'Anonymous FTP login enabled',
    detail: 'The FTP service allows anonymous login, exposing a file named note_to_jake.txt.',
    severity: 'medium',
  },
  {
    title: 'Weak SSH credentials',
    detail: 'A user account (jake) uses a weak, brute-forceable SSH password.',
    severity: 'high',
  },
  {
    title: 'Hidden file found via directory brute-force',
    detail: 'A file named photo.jpg was found through directory enumeration; it is not linked from the site and contains a steganography clue.',
    severity: 'low',
  },
] as const;
