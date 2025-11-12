'use client';

import { ScanProgress as ScanProgressType } from '@/lib/types';

interface ScanProgressProps {
  progress: ScanProgressType;
}

export default function ScanProgress({ progress }: ScanProgressProps) {
  return (
    <div className="bg-slate-800 rounded-lg border border-slate-700 p-6 mb-6">
      <h2 className="text-xl font-semibold text-white mb-4">Scan Progress</h2>
      <div className="space-y-4">
        <div>
          <div className="flex justify-between text-sm mb-2">
            <span className="text-slate-400">Port Scanning</span>
            <span className="text-white font-medium">{progress.portScanning}%</span>
          </div>
          <div className="w-full bg-slate-700 rounded-full h-2">
            <div
              className="bg-blue-500 h-2 rounded-full transition-all duration-300"
              style={{ width: `${progress.portScanning}%` }}
            ></div>
          </div>
        </div>
        <div className="pt-2 border-t border-slate-700">
          <p className="text-sm text-slate-400 mb-1">Current Target</p>
          <p className="text-white font-medium">{progress.currentTarget}</p>
        </div>
        <div>
          <p className="text-sm text-slate-400 mb-1">Ports Scanned</p>
          <p className="text-white font-medium">
            {progress.portsScanned.toLocaleString()} / {progress.totalPorts.toLocaleString()}
          </p>
        </div>
      </div>
    </div>
  );
}

