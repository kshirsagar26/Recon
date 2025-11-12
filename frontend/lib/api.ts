import axios from 'axios';
import { ScanResult, SummaryStats, VulnerabilityStats, ScanProgress } from './types';

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const apiService = {
  // Get all scan results (optionally filtered by root domain)
  getScanResults: async (rootDomain?: string): Promise<ScanResult[]> => {
    try {
      const params = rootDomain ? { root_domain: rootDomain } : {};
      const response = await api.get('/api/scans', { params });
      return response.data.results || [];
    } catch (error) {
      console.error('Error fetching scan results:', error);
      return [];
    }
  },

  // Get summary statistics
  getSummaryStats: async (): Promise<SummaryStats> => {
    try {
      const response = await api.get('/api/stats');
      return response.data;
    } catch (error) {
      console.error('Error fetching stats:', error);
      return {
        subdomains: 0,
        vulnerabilities: 0,
        activeIPs: 0,
        totalScans: 0,
      };
    }
  },

  // Get vulnerability statistics
  getVulnerabilityStats: async (): Promise<VulnerabilityStats> => {
    try {
      const response = await api.get('/api/vulnerabilities');
      return response.data;
    } catch (error) {
      console.error('Error fetching vulnerability stats:', error);
      return {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
      };
    }
  },

  // Get scan progress
  getScanProgress: async (): Promise<ScanProgress> => {
    try {
      const response = await api.get('/api/scan-progress');
      return response.data;
    } catch (error) {
      console.error('Error fetching scan progress:', error);
      return {
        portScanning: 0,
        currentTarget: '',
        portsScanned: 0,
        totalPorts: 10000,
      };
    }
  },

  // Start a new scan
  startScan: async (domain: string): Promise<void> => {
    await api.post('/api/scans/start', { domain });
  },

  // Search
  search: async (query: string): Promise<ScanResult[]> => {
    try {
      const response = await api.get('/api/search', { params: { query } });
      return response.data.results || [];
    } catch (error) {
      console.error('Error searching:', error);
      return [];
    }
  },
};

