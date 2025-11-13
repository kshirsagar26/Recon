'use client';

import { useEffect, useState, useRef } from 'react';
import Header from '@/components/Header';
import SummaryCards from '@/components/SummaryCards';
import ScanResultsTable from '@/components/ScanResultsTable';
import VulnerabilityChart from '@/components/VulnerabilityChart';
import ScanProgress from '@/components/ScanProgress';
import Reports from '@/components/Reports';
import { apiService } from '@/lib/api';
import { ScanResult, SummaryStats, VulnerabilityStats, ScanProgress as ScanProgressType } from '@/lib/types';
import { Toaster } from 'react-hot-toast';

export default function Home() {
  const [scanResults, setScanResults] = useState<ScanResult[]>([]);
  const [summaryStats, setSummaryStats] = useState<SummaryStats>({
    subdomains: 0,
    vulnerabilities: 0,
    activeIPs: 0,
    totalScans: 0,
  });
  const [vulnerabilityStats, setVulnerabilityStats] = useState<VulnerabilityStats>({
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  });
  const [scanProgress, setScanProgress] = useState<ScanProgressType>({
    portScanning: 0,
    currentTarget: '',
    portsScanned: 0,
    totalPorts: 0,
  });
  const [loading, setLoading] = useState(true);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [results, stats, vulnStats, progress] = await Promise.all([
          apiService.getScanResults(), // Will return only current scan results
          apiService.getSummaryStats(),
          apiService.getVulnerabilityStats(),
          apiService.getScanProgress(),
        ]);

        // Only show results if there's a current target, otherwise show empty
        const currentTarget = progress.currentTarget;
        if (currentTarget) {
          // Filter to show only current target's results
          const filteredResults = results.filter(r => {
            // Check if result belongs to current target domain
            const resultDomain = r.domain;
            return resultDomain.includes(currentTarget) || currentTarget.includes(resultDomain.split('.')[0]);
          });
          setScanResults(filteredResults.length > 0 ? filteredResults : results);
        } else {
          setScanResults(results);
        }
        
        setSummaryStats(stats);
        setVulnerabilityStats(vulnStats);
        setScanProgress(progress);
      } catch (error) {
        console.error('Error fetching data:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchData();

    // Connect to WebSocket for real-time updates
    const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
    const wsUrl = API_BASE_URL.replace('http', 'ws') + '/ws/scan-progress';
    
    try {
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        console.log('WebSocket connected');
      };

      ws.onmessage = (event) => {
        try {
          const progress = JSON.parse(event.data);
          setScanProgress(progress);
        } catch (error) {
          console.error('Error parsing WebSocket message:', error);
        }
      };

      ws.onerror = (error) => {
        console.error('WebSocket error:', error);
        // Fallback to polling if WebSocket fails
        const interval = setInterval(async () => {
          try {
            const progress = await apiService.getScanProgress();
            setScanProgress(progress);
          } catch (error) {
            console.error('Error updating progress:', error);
          }
        }, 2000);
        return () => clearInterval(interval);
      };

      ws.onclose = () => {
        console.log('WebSocket disconnected');
      };
    } catch (error) {
      console.error('Failed to connect WebSocket, using polling:', error);
      // Fallback to polling
      const interval = setInterval(async () => {
        try {
          const progress = await apiService.getScanProgress();
          setScanProgress(progress);
        } catch (error) {
          console.error('Error updating progress:', error);
        }
      }, 2000);
      return () => clearInterval(interval);
    }

    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, []);

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-900 flex items-center justify-center">
        <div className="text-white text-xl">Loading...</div>
      </div>
    );
  }

  const handleSearchResults = (results: ScanResult[]) => {
    setScanResults(results);
  };

  const handleScanStarted = async () => {
    // Refresh all data after scan completes
    try {
      const [results, stats, vulnStats, progress] = await Promise.all([
        apiService.getScanResults(),
        apiService.getSummaryStats(),
        apiService.getVulnerabilityStats(),
        apiService.getScanProgress(),
      ]);
      
      // Filter results to current target if available
      const currentTarget = progress.currentTarget;
      if (currentTarget) {
        const filteredResults = results.filter(r => {
          const resultDomain = r.domain.toLowerCase();
          const targetDomain = currentTarget.toLowerCase();
          return resultDomain.includes(targetDomain) || resultDomain.endsWith('.' + targetDomain);
        });
        setScanResults(filteredResults.length > 0 ? filteredResults : results);
      } else {
        setScanResults(results);
      }
      
      setSummaryStats(stats);
      setVulnerabilityStats(vulnStats);
      setScanProgress(progress);
    } catch (error) {
      console.error('Error refreshing data:', error);
    }
  };

  return (
    <div className="min-h-screen bg-slate-900">
      <Header onSearchResults={handleSearchResults} onScanStarted={handleScanStarted} />
      <main className="p-6">
        <SummaryCards stats={summaryStats} />
        <div className="grid grid-cols-3 gap-6">
          <div className="col-span-2 space-y-6">
            <ScanResultsTable results={scanResults} />
            <VulnerabilityChart stats={vulnerabilityStats} />
          </div>
          <div className="space-y-6">
            <ScanProgress progress={scanProgress} />
            <Reports scanResults={scanResults} />
          </div>
        </div>
      </main>
      <Toaster position="top-right" />
    </div>
  );
}

