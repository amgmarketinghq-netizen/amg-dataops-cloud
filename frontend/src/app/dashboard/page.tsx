'use client';

import React, { useState } from 'react';
import { 
  Upload, 
  ShieldAlert, 
  CheckCircle, 
  AlertTriangle, 
  FileText, 
  Cpu, 
  RefreshCw,
  Search,
  Filter,
  Download
} from 'lucide-react';

export default function DashboardPage() {
  const [isProcessing, setIsProcessing] = useState(false);
  const [records, setRecords] = useState<any[]>([]);
  const [report, setReport] = useState<any>(null);

  // Handle File Upload Simulation
  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setIsProcessing(true);
    
    // Simulating Real API processing connection to FastAPI backend
    setTimeout(() => {
      setIsProcessing(false);
      setReport({
        total: 1250,
        clean: 1180,
        duplicates: 45,
        highRisk: 25,
        processingTime: '142ms'
      });
      
      setRecords([
        { id: 1, email: 'alex.smith@enterprise.com', phone: '+14155552671', risk: 12, status: 'VALID_MX', sector: 'IT & SaaS', carrier: 'Verizon' },
        { id: 2, email: 'john_fake@tempmail.org', phone: '+14155550199', risk: 88, status: 'DISPOSABLE', sector: 'Unknown', carrier: 'VoIP' },
        { id: 3, email: 'contact@marketing-corp.co', phone: '+442071838750', risk: 24, status: 'VALID_MX', sector: 'Marketing', carrier: 'BT Group' },
        { id: 4, email: 'admin@phishing-test.xyz', phone: '+18005550122', risk: 95, status: 'HIGH_RISK_TLD', sector: 'Unclassified', carrier: 'Dummy' },
      ]);
    }, 1200);
  };

  return (
    <div className="min-h-screen bg-[#080C14] text-slate-100 flex flex-col font-sans">
      
      {/* Top Header */}
      <header className="border-b border-white/10 bg-[#0B0F19] px-6 py-4 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="h-8 w-8 rounded-lg bg-[#00F2FE] flex items-center justify-center text-black font-bold">
            <Cpu className="w-5 h-5 text-black" />
          </div>
          <span className="font-bold text-lg tracking-wider text-white">
            AMG DATAOPS <span className="text-[#00F2FE] text-xs px-2 py-0.5 rounded bg-[#00F2FE]/10 border border-[#00F2FE]/20">WORKSPACE</span>
          </span>
        </div>

        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2 text-xs font-mono bg-[#080C14] px-3 py-1.5 rounded-lg border border-white/10">
            <span className="h-2 w-2 rounded-full bg-[#10B981] animate-pulse" />
            <span className="text-slate-300">ENGINES 01-09: ONLINE</span>
          </div>
          <a href="/admin" className="text-xs text-slate-400 hover:text-white transition">Admin Panel</a>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="flex-1 p-6 max-w-7xl mx-auto w-full space-y-6">
        
        {/* Upload & Pipeline Status Header */}
        <div className="grid md:grid-cols-3 gap-6">
          
          {/* CSV File Dropzone */}
          <div className="md:col-span-2 border-2 border-dashed border-white/10 hover:border-[#00F2FE]/50 bg-[#0B0F19] rounded-2xl p-8 flex flex-col items-center justify-center transition group relative cursor-pointer">
            <input 
              type="file" 
              accept=".csv,.txt" 
              onChange={handleFileUpload} 
              className="absolute inset-0 opacity-0 cursor-pointer"
            />
            <div className="h-12 w-12 rounded-xl bg-[#00F2FE]/10 flex items-center justify-center text-[#00F2FE] mb-3 group-hover:scale-110 transition">
              {isProcessing ? <RefreshCw className="w-6 h-6 animate-spin" /> : <Upload className="w-6 h-6" />}
            </div>
            <h3 className="font-semibold text-lg text-white mb-1">
              {isProcessing ? "Executing 9-Engine Processing..." : "Upload CSV Data Batch"}
            </h3>
            <p className="text-xs text-slate-400">Drag & drop your CSV file here to trigger sanitization, MX probe & risk scoring</p>
          </div>

          {/* Quick Metrics Card */}
          <div className="bg-[#0B0F19] border border-white/10 rounded-2xl p-6 flex flex-col justify-between">
            <div>
              <div className="text-xs font-mono text-slate-400 mb-1">CURRENT BATCH SUMMARY</div>
              <div className="text-3xl font-extrabold text-white">
                {report ? report.clean : 0} <span className="text-xs font-normal text-slate-400">/ {report ? report.total : 0} Clean Records</span>
              </div>
            </div>

            <div className="space-y-2 mt-4 pt-4 border-t border-white/10 text-xs">
              <div className="flex justify-between text-slate-400">
                <span>Duplicates Removed:</span>
                <span className="text-white font-mono">{report ? report.duplicates : 0}</span>
              </div>
              <div className="flex justify-between text-slate-400">
                <span>High Risk Flagged:</span>
                <span className="text-[#EF4444] font-mono">{report ? report.highRisk : 0}</span>
              </div>
              <div className="flex justify-between text-slate-400">
                <span>Processing Latency:</span>
                <span className="text-[#10B981] font-mono">{report ? report.processingTime : '0ms'}</span>
              </div>
            </div>
          </div>

        </div>

        {/* Data Grid Section */}
        <div className="bg-[#0B0F19] border border-white/10 rounded-2xl overflow-hidden">
          
          {/* Table Control Bar */}
          <div className="p-4 border-b border-white/10 flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <span className="font-semibold text-sm">Processed Results Grid</span>
              <span className="text-xs bg-white/5 px-2.5 py-1 rounded-full text-slate-400 font-mono">
                {records.length} Records Loaded
              </span>
            </div>

            <div className="flex items-center space-x-3">
              <button className="px-3 py-1.5 rounded-lg border border-white/10 text-xs text-slate-300 hover:bg-white/5 flex items-center space-x-1.5">
                <Download className="w-3.5 h-3.5" />
                <span>Export Clean CSV</span>
              </button>
            </div>
          </div>

          {/* High-Density Data Table */}
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-[#080C14] text-slate-400 border-b border-white/10 uppercase tracking-wider">
                <tr>
                  <th className="py-3 px-4">Record ID</th>
                  <th className="py-3 px-4">Email Address</th>
                  <th className="py-3 px-4">Phone (E.164)</th>
                  <th className="py-3 px-4">Verification Tag</th>
                  <th className="py-3 px-4">B2B Sector</th>
                  <th className="py-3 px-4 text-right">Risk Score</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5 text-slate-300">
                {records.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-12 text-center text-slate-500 font-sans">
                      No batch processed yet. Upload a CSV file above to run live pipelines.
                    </td>
                  </tr>
                ) : (
                  records.map((row) => (
                    <tr key={row.id} className="hover:bg-white/[0.02] transition">
                      <td className="py-3 px-4 text-slate-500">#00{row.id}</td>
                      <td className="py-3 px-4 font-semibold text-white">{row.email}</td>
                      <td className="py-3 px-4 text-slate-400">{row.phone}</td>
                      <td className="py-3 px-4">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          row.status === 'VALID_MX' ? 'bg-[#10B981]/10 text-[#10B981] border border-[#10B981]/30' :
                          'bg-[#EF4444]/10 text-[#EF4444] border border-[#EF4444]/30'
                        }`}>
                          {row.status}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-slate-400">{row.sector}</td>
                      <td className="py-3 px-4 text-right">
                        <span className={`font-bold ${row.risk > 70 ? 'text-[#EF4444]' : 'text-[#10B981]'}`}>
                          {row.risk}/100
                        </span>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

        </div>

      </main>
    </div>
  );
}
