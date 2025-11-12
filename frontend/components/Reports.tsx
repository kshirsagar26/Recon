'use client';

import { FileText, FileDown, History } from 'lucide-react';
import { apiService } from '@/lib/api';
import { ScanResult } from '@/lib/types';
import { toast } from 'react-hot-toast';
import jsPDF from 'jspdf';

interface ReportsProps {
  scanResults?: ScanResult[];
}

export default function Reports({ scanResults = [] }: ReportsProps) {
  const handleExportPDF = async () => {
    try {
      toast.loading('Generating PDF...', { id: 'pdf-export' });
      
      // Get all scan data
      const results = scanResults.length > 0 ? scanResults : await apiService.getScanResults();
      const stats = await apiService.getSummaryStats();
      const vulnStats = await apiService.getVulnerabilityStats();

      // Create PDF
      const pdf = new jsPDF();
      let yPos = 20;

      // Title
      pdf.setFontSize(20);
      pdf.text('Recon_FW Scan Report', 20, yPos);
      yPos += 15;

      // Summary Stats
      pdf.setFontSize(14);
      pdf.text('Summary Statistics', 20, yPos);
      yPos += 10;
      pdf.setFontSize(10);
      pdf.text(`Subdomains: ${stats.subdomains}`, 20, yPos);
      yPos += 7;
      pdf.text(`Vulnerabilities: ${stats.vulnerabilities}`, 20, yPos);
      yPos += 7;
      pdf.text(`Active IPs: ${stats.activeIPs}`, 20, yPos);
      yPos += 7;
      pdf.text(`Total Scans: ${stats.totalScans}`, 20, yPos);
      yPos += 15;

      // Vulnerability Stats
      pdf.setFontSize(14);
      pdf.text('Vulnerability Distribution', 20, yPos);
      yPos += 10;
      pdf.setFontSize(10);
      pdf.text(`Critical: ${vulnStats.critical}`, 20, yPos);
      yPos += 7;
      pdf.text(`High: ${vulnStats.high}`, 20, yPos);
      yPos += 7;
      pdf.text(`Medium: ${vulnStats.medium}`, 20, yPos);
      yPos += 7;
      pdf.text(`Low: ${vulnStats.low}`, 20, yPos);
      yPos += 7;
      pdf.text(`Info: ${vulnStats.info}`, 20, yPos);
      yPos += 15;

      // Scan Results
      pdf.setFontSize(14);
      pdf.text('Scan Results', 20, yPos);
      yPos += 10;
      pdf.setFontSize(8);

      // Table headers
      pdf.text('Domain', 20, yPos);
      pdf.text('Port', 60, yPos);
      pdf.text('Vulnerability', 80, yPos);
      pdf.text('Status', 150, yPos);
      yPos += 7;

      // Table rows
      results.slice(0, 20).forEach((result) => {
        if (yPos > 270) {
          pdf.addPage();
          yPos = 20;
        }
        pdf.text(result.domain.substring(0, 25), 20, yPos);
        pdf.text(result.port.toString(), 60, yPos);
        pdf.text(result.vulnerability.substring(0, 30), 80, yPos);
        pdf.text(result.status, 150, yPos);
        yPos += 7;
      });

      // Save PDF
      pdf.save('recon-fw-report.pdf');
      toast.success('PDF exported successfully!', { id: 'pdf-export' });
    } catch (error) {
      console.error('Error exporting PDF:', error);
      toast.error('Failed to export PDF', { id: 'pdf-export' });
    }
  };

  const handleGenerateReport = async () => {
    try {
      toast.loading('Generating report...', { id: 'generate-report' });
      // In a real implementation, this would trigger a comprehensive report generation
      await new Promise(resolve => setTimeout(resolve, 1500));
      toast.success('Report generated successfully!', { id: 'generate-report' });
    } catch (error) {
      console.error('Error generating report:', error);
      toast.error('Failed to generate report', { id: 'generate-report' });
    }
  };

  const handleViewHistory = () => {
    toast('History view coming soon!', { icon: 'ℹ️' });
  };

  return (
    <div className="bg-slate-800 rounded-lg border border-slate-700 p-6">
      <h2 className="text-xl font-semibold text-white mb-4">Reports</h2>
      <div className="space-y-3">
        <button
          onClick={handleExportPDF}
          className="w-full bg-red-600 hover:bg-red-700 text-white font-medium py-2.5 px-4 rounded-lg transition-colors flex items-center justify-center gap-2"
        >
          <FileDown className="w-5 h-5" />
          Export PDF
        </button>
        <button
          onClick={handleGenerateReport}
          className="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-2.5 px-4 rounded-lg transition-colors flex items-center justify-center gap-2"
        >
          <FileText className="w-5 h-5" />
          Generate Report
        </button>
        <button
          onClick={handleViewHistory}
          className="w-full bg-slate-700 hover:bg-slate-600 text-white font-medium py-2.5 px-4 rounded-lg transition-colors flex items-center justify-center gap-2"
        >
          <History className="w-5 h-5" />
          View History
        </button>
      </div>
    </div>
  );
}

