'use client';

import { ScanResult } from '@/lib/types';
import { AlertCircle, AlertTriangle, CheckCircle } from 'lucide-react';

interface ScanResultsTableProps {
  results: ScanResult[];
}

export default function ScanResultsTable({ results }: ScanResultsTableProps) {
  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'Critical':
        return <AlertCircle className="w-5 h-5 text-red-500" />;
      case 'Warning':
        return <AlertTriangle className="w-5 h-5 text-yellow-500" />;
      case 'Safe':
        return <CheckCircle className="w-5 h-5 text-green-500" />;
      default:
        return null;
    }
  };

  const getStatusBadge = (status: string) => {
    const baseClasses = 'px-3 py-1 rounded-full text-xs font-medium';
    switch (status) {
      case 'Critical':
        return `${baseClasses} bg-red-500/20 text-red-400 border border-red-500/30`;
      case 'Warning':
        return `${baseClasses} bg-yellow-500/20 text-yellow-400 border border-yellow-500/30`;
      case 'Safe':
        return `${baseClasses} bg-green-500/20 text-green-400 border border-green-500/30`;
      default:
        return baseClasses;
    }
  };

  return (
    <div className="bg-slate-800 rounded-lg border border-slate-700 overflow-hidden">
      <div className="px-6 py-4 border-b border-slate-700 flex items-center justify-between">
        <h2 className="text-xl font-semibold text-white">Scan Results</h2>
        <span className="text-sm text-slate-400">
          {results.length} {results.length === 1 ? 'result' : 'results'}
        </span>
      </div>
      <div className="overflow-x-auto max-h-[600px] overflow-y-auto">
        <table className="w-full">
          <thead className="bg-slate-900/50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                Domain
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                Port
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                Vulnerability
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                CVE Data
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                Status
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-700">
            {results.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-6 py-12 text-center">
                  <p className="text-slate-400">No scan results found</p>
                  <p className="text-sm text-slate-500 mt-2">Start a scan to see results</p>
                </td>
              </tr>
            ) : (
              results.map((result) => (
                <tr
                  key={result.id}
                  className="hover:bg-slate-700/50 transition-colors"
                >
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-white font-mono">
                    {result.domain}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-300">
                    {result.port}
                  </td>
                  <td className="px-6 py-4 text-sm text-slate-300">
                    {result.vulnerability}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-300 font-mono">
                    {result.cveData}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center gap-2">
                      {getStatusIcon(result.status)}
                      <span className={getStatusBadge(result.status)}>
                        {result.status}
                      </span>
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

