export interface ScanResult {
  id: string;
  domain: string;
  port: number;
  vulnerability: string;
  cveData: string;
  status: 'Critical' | 'Warning' | 'Safe';
  subdomains?: string[]; // Optional: for backward compatibility
}

export interface SummaryStats {
  subdomains: number;
  vulnerabilities: number;
  activeIPs: number;
  totalScans: number;
}

export interface VulnerabilityStats {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface ScanProgress {
  portScanning: number;
  currentTarget: string;
  portsScanned: number;
  totalPorts: number;
}

