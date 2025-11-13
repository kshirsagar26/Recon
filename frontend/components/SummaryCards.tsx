'use client';

import { Globe, AlertTriangle, Activity, Database } from 'lucide-react';
import { SummaryStats } from '@/lib/types';

interface SummaryCardsProps {
  stats: SummaryStats;
}

export default function SummaryCards({ stats }: SummaryCardsProps) {
  const cards = [
    {
      title: 'Subdomains',
      value: stats.subdomains.toLocaleString(),
      icon: Globe,
      color: 'text-blue-400',
    },
    {
      title: 'Vulnerabilities',
      value: stats.vulnerabilities,
      icon: AlertTriangle,
      color: 'text-red-400',
    },
    {
      title: 'Active IPs',
      value: stats.activeIPs,
      icon: Activity,
      color: 'text-green-400',
    },
    {
      title: 'Total Scans',
      value: stats.totalScans,
      icon: Database,
      color: 'text-purple-400',
    },
  ];

  return (
    <div className="grid grid-cols-4 gap-6 mb-6">
      {cards.map((card) => {
        const Icon = card.icon;
        return (
          <div
            key={card.title}
            className="bg-slate-800 rounded-lg p-6 border border-slate-700"
          >
            <div className="flex items-center justify-between">
              <div>
                <p className="text-slate-400 text-sm mb-2">{card.title}</p>
                <p className="text-2xl font-bold text-white">{card.value}</p>
              </div>
              <Icon className={`w-8 h-8 ${card.color}`} />
            </div>
          </div>
        );
      })}
    </div>
  );
}

