'use client';

import { useState, useEffect } from 'react';
import { Search, Bell, User, Play } from 'lucide-react';
import { apiService } from '@/lib/api';
import { ScanResult } from '@/lib/types';
import { toast } from 'react-hot-toast';

interface HeaderProps {
  onSearchResults?: (results: ScanResult[]) => void;
  onScanStarted?: () => void;
}

export default function Header({ onSearchResults, onScanStarted }: HeaderProps) {
  const [searchQuery, setSearchQuery] = useState('');
  const [searchTimeout, setSearchTimeout] = useState<NodeJS.Timeout | null>(null);
  const [isScanning, setIsScanning] = useState(false);

  useEffect(() => {
    // Debounce search
    if (searchTimeout) {
      clearTimeout(searchTimeout);
    }

    if (searchQuery.trim()) {
      const timeout = setTimeout(async () => {
        try {
          const results = await apiService.search(searchQuery);
          if (onSearchResults) {
            onSearchResults(results);
          }
        } catch (error) {
          console.error('Search error:', error);
        }
      }, 500); // Wait 500ms after user stops typing

      setSearchTimeout(timeout);
    } else {
      // If search is empty, show all results
      if (onSearchResults) {
        apiService.getScanResults().then(onSearchResults);
      }
    }

    return () => {
      if (searchTimeout) {
        clearTimeout(searchTimeout);
      }
    };
  }, [searchQuery, onSearchResults]);

  const handleStartScan = async () => {
    if (!searchQuery.trim()) {
      toast.error('Please enter a domain to scan');
      return;
    }

    // Check if it looks like a domain
    const domainPattern = /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
    if (!domainPattern.test(searchQuery.trim())) {
      toast.error('Please enter a valid domain (e.g., example.com)');
      return;
    }

    setIsScanning(true);
    const domainToScan = searchQuery.trim().replace(/^https?:\/\//, "").replace(/^www\./, "").trim();
    
    try {
      toast.loading(`Starting scan for ${domainToScan}...`, { id: 'start-scan' });
      await apiService.startScan(domainToScan);
      toast.success('Scan started successfully!', { id: 'start-scan' });
      
      // Clear search query to show all results
      setSearchQuery('');
      
      // Refresh results after scan completes (wait longer for enumeration to finish)
      setTimeout(async () => {
        // Poll for results multiple times as scan completes
        const pollResults = async (attempts = 0) => {
          try {
            // Get results filtered by the domain we just scanned
            const results = await apiService.getScanResults(domainToScan);
            // Filter to ensure we only show results for the scanned domain
            const filteredResults = results.filter(r => {
              const resultDomain = r.domain.toLowerCase();
              const targetDomain = domainToScan.toLowerCase();
              return resultDomain.includes(targetDomain) || resultDomain.endsWith('.' + targetDomain);
            });
            if (onSearchResults) {
              onSearchResults(filteredResults.length > 0 ? filteredResults : results);
            }
            
            // Refresh stats on each poll to update the count
            if (onScanStarted) {
              onScanStarted();
            }
            
            // Continue polling if scan might still be running (up to 15 attempts = 45 seconds)
            if (attempts < 15) {
              setTimeout(() => pollResults(attempts + 1), 3000);
            }
          } catch (error) {
            console.error('Error polling results:', error);
          }
        };
        
        // Start polling after initial delay (give time for enumeration to start)
        setTimeout(() => pollResults(), 5000);
      }, 1000);
    } catch (error) {
      console.error('Error starting scan:', error);
      toast.error('Failed to start scan', { id: 'start-scan' });
    } finally {
      setIsScanning(false);
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      handleStartScan();
    }
  };

  return (
    <header className="bg-slate-900 border-b border-slate-800 px-6 py-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-8">
          <h1 className="text-2xl font-bold text-white">Recon_FW</h1>
          <div className="relative flex items-center gap-2">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-slate-400 w-5 h-5" />
              <input
                type="text"
                placeholder="Search or scan domain (e.g., example.com)"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                onKeyPress={handleKeyPress}
                className="bg-slate-800 text-white placeholder-slate-400 pl-10 pr-4 py-2 rounded-lg w-80 border border-slate-700 focus:outline-none focus:border-slate-600"
              />
            </div>
            <button
              onClick={handleStartScan}
              disabled={isScanning || !searchQuery.trim()}
              className="bg-blue-600 hover:bg-blue-700 disabled:bg-slate-700 disabled:cursor-not-allowed text-white px-4 py-2 rounded-lg flex items-center gap-2 transition-colors"
              title="Start scan for this domain"
            >
              <Play className="w-4 h-4" />
              {isScanning ? 'Scanning...' : 'Scan'}
            </button>
          </div>
        </div>
        <div className="flex items-center gap-4">
          <div className="relative">
            <Bell className="text-slate-400 w-6 h-6 cursor-pointer hover:text-white" />
            <span className="absolute -top-1 -right-1 w-3 h-3 bg-red-500 rounded-full"></span>
          </div>
          <div className="w-8 h-8 bg-slate-700 rounded-full flex items-center justify-center cursor-pointer hover:bg-slate-600">
            <User className="text-slate-300 w-5 h-5" />
          </div>
        </div>
      </div>
    </header>
  );
}

