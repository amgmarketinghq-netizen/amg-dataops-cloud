'use client';

import React, { useState } from 'react';
import { 
  ShieldAlert, 
  Cpu, 
  Activity, 
  Key, 
  Users, 
  AlertOctagon, 
  Database, 
  Terminal, 
  CheckCircle2, 
  XCircle, 
  Sliders, 
  Power,
  RefreshCcw
} from 'lucide-react';

export default function AdminPage() {
  const [circuitBreakerOpen, setCircuitBreakerOpen] = useState(false);

  return (
    <div className="min-h-screen bg-[#05080E] text-slate-100 flex flex-col font-sans">
      
      {/* Top Admin Header */}
      <header className="border-b border-white/10 bg-[#080C14] px-6 py-4 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="h-8 w-8 rounded-lg bg-[#EF4444] flex items-center justify-center text-black font-bold">
            <ShieldAlert className="w-5 h-5 text-white" />
          </div>
          <span className="font-bold text-lg tracking-wider text-white">
            AMG DATAOPS <span className="text-[#EF4444] text-xs px-2 py-0.5 rounded bg-[#EF4444]/10 border border-[#EF4444]/30 font-mono">MASTER COMMAND CENTER</span>
          </span>
        </div>

        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2 text-xs font-mono bg-[#05080E] px-3 py-1.5 rounded-lg border border-white/10">
            <span className={`h-2 w-2 rounded-full ${circuitBreakerOpen ? 'bg-[#EF4444]' : 'bg-[#10B981]'} animate-pulse`} />
            <span>CIRCUIT BREAKER: {circuitBreakerOpen ? 'TRIPPED (OPEN)' : 'HEALTHY (CLOSED)'}</span>
          </div>
          <a href="/dashboard" className="text-xs text-[#00F2FE] hover:underline">User Dashboard ➔</a>
        </div>
      </header>

      {/* Main Admin View */}
      <main className="flex-1 p-6 max-w-7xl mx-auto w-full space-y-6">
        
        {/* System Health Metric Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-[#080C14] border border-white/10 p-5 rounded-xl">
            <div className="flex items-center justify-between text-slate-400 text-xs mb-2">
              <span>ACTIVE TENANTS</span>
              <Users className="w-4 h-4 text-[#00F2FE]" />
            </div>
            <div className="text-2xl font-bold font-mono text-white">12 Organizations</div>
            <div className="text-[10px] text-[#10B981] mt-1">+2 onboarded today</div>
          </div>

          <div className="bg-[#080C14] border border-white/10 p-5 rounded-xl">
            <div className="flex items-center justify-between text-slate-400 text-xs mb-2">
              <span>THROTTLED REQUESTS (ENG-07)</span>
              <Activity className="w-4 h-4 text-[#F59E0B]" />
            </div>
            <div className="text-2xl font-bold font-mono text-white">412 / min</div>
            <div className="text-[10px] text-slate-400 mt-1">Token Bucket Capacity: 60/sec</div>
          </div>

          <div className="bg-[#080C14] border border-white/10 p-5 rounded-xl">
            <div className="flex items-center justify-between text-slate-400 text-xs mb-2">
              <span>DLQ UNRECONCILED (ENG-09)</span>
              <AlertOctagon className="w-4 h-4 text-[#EF4444]" />
            </div>
            <div className="text-2xl font-bold font-mono text-[#EF4444]">3 Records</div>
            <div className="text-[10px] text-slate-400 mt-1">Requires admin manual flush</div>
          </div>

          <div className="bg-[#080C14] border border-white/10 p-5 rounded-xl">
            <div className="flex items-center justify-between text-slate-400 text-xs mb-2">
              <span>MERKLE HASH CHAIN TIP</span>
              <Database className="w-4 h-4 text-[#A855F7]" />
            </div>
            <div className="text-xs font-mono text-slate-300 truncate mt-1">8f3a9e102bc4d0...</div>
            <div className="text-[10px] text-[#10B981] mt-1">Audit verification: PASSED</div>
          </div>
        </div>

        {/* 9-Engine Status Control Grid */}
        <div className="bg-[#080C14] border border-white/10 rounded-2xl p-6">
          <div className="flex items-center justify-between mb-6">
            <div>
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <Cpu className="w-4 h-4 text-[#00F2FE]" /> 9-Engine Live Status & Controls
              </h2>
              <p className="text-xs text-slate-400">Manage global thresholds, circuit breakers, and worker pools</p>
            </div>

            <button 
              onClick={() => setCircuitBreakerOpen(!circuitBreakerOpen)}
              className={`px-4 py-2 rounded-xl text-xs font-bold font-mono flex items-center gap-2 transition ${
                circuitBreakerOpen ? 'bg-[#10B981] text-black' : 'bg-[#EF4444] text-white hover:bg-red-600'
              }`}
            >
              <Power className="w-4 h-4" />
              <span>{circuitBreakerOpen ? 'RESET CIRCUIT BREAKER' : 'FORCE EMERGENCY TRIP'}</span>
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono text-xs">
            {[
              { id: "01", name: "Normalization", status: "HEALTHY", latency: "1.2ms" },
              { id: "02", name: "Deduplication", status: "HEALTHY", latency: "0.8ms" },
              { id: "03", name: "Deep Email MX", status: "HEALTHY", latency: "142ms" },
              { id: "04", name: "Phone E.164", status: "HEALTHY", latency: "12ms" },
              { id: "05", name: "Threat Scoring", status: "HEALTHY", latency: "4.5ms" },
              { id: "06", name: "AST Rules Linter", status: "HEALTHY", latency: "2.1ms" },
              { id: "07", name: "Throttling & Buckets", status: circuitBreakerOpen ? "TRIPPED" : "HEALTHY", latency: "0.1ms" },
              { id: "08", name: "Merkle Audit Chain", status: "HEALTHY", latency: "3.2ms" },
              { id: "09", name: "Orchestrator & DLQ", status: "HEALTHY", latency: "1.0ms" },
            ].map((e) => (
              <div key={e.id} className="p-3 bg-[#05080E] border border-white/5 rounded-xl flex items-center justify-between">
                <div>
                  <div className="font-bold text-white">ENG-{e.id}: {e.name}</div>
                  <div className="text-[10px] text-slate-500">Latency: {e.latency}</div>
                </div>
                <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                  e.status === 'HEALTHY' ? 'bg-[#10B981]/10 text-[#10B981]' : 'bg-[#EF4444]/10 text-[#EF4444]'
                }`}>
                  {e.status}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Tenant Management Table */}
        <div className="bg-[#080C14] border border-white/10 rounded-2xl overflow-hidden">
          <div className="p-4 border-b border-white/10 flex items-center justify-between">
            <span className="font-semibold text-sm">Tenant Provisioning & API Quotas</span>
            <button className="px-3 py-1.5 rounded-lg bg-[#00F2FE] text-black text-xs font-bold">
              + Provision New Tenant
            </button>
          </div>

          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-[#05080E] text-slate-400 border-b border-white/10">
              <tr>
                <th className="py-3 px-4">Tenant ID</th>
                <th className="py-3 px-4">Organization</th>
                <th className="py-3 px-4">Plan Tier</th>
                <th className="py-3 px-4">Rate Limit</th>
                <th className="py-3 px-4">API Key Status</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5 text-slate-300">
              <tr>
                <td className="py-3 px-4 text-slate-500">tenant_amg_prod_01</td>
                <td className="py-3 px-4 font-bold text-white">AMG Marketing Global</td>
                <td className="py-3 px-4 text-[#00F2FE]">ENTERPRISE_CUSTOM</td>
                <td className="py-3 px-4 text-slate-400">100 req/sec</td>
                <td className="py-3 px-4">
                  <span className="px-2 py-0.5 rounded text-[10px] bg-[#10B981]/10 text-[#10B981]">ACTIVE</span>
                </td>
                <td className="py-3 px-4 text-right">
                  <button className="text-slate-400 hover:text-[#EF4444]">Revoke Key</button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>

      </main>
    </div>
  );
}
