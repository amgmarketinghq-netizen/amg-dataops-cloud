import React from 'react';
import { 
  ShieldCheck, 
  Cpu, 
  Zap, 
  CheckCircle2, 
  ArrowRight,
  Lock,
  Database,
  Server,
  Terminal
} from 'lucide-react';

export default function LandingPage() {
  return (
    <div className="min-h-screen bg-[#080C14] text-white selection:bg-[#00F2FE] selection:text-black">
      
      {/* Top Navigation */}
      <nav className="border-b border-white/10 bg-[#080C14]/80 backdrop-blur-md sticky top-0 z-50 px-6 py-4 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="h-9 w-9 rounded-xl bg-gradient-to-tr from-[#00F2FE] to-[#A855F7] p-[1px]">
            <div className="h-full w-full bg-[#080C14] rounded-[11px] flex items-center justify-center">
              <Cpu className="w-5 h-5 text-[#00F2FE]" />
            </div>
          </div>
          <span className="font-bold text-xl tracking-wider bg-clip-text text-transparent bg-gradient-to-r from-white via-slate-200 to-slate-400">
            AMG DATAOPS
          </span>
        </div>
        
        <div className="flex items-center space-x-6 text-sm font-medium">
          <a href="#engines" className="text-slate-400 hover:text-white transition">Engines</a>
          <a href="#security" className="text-slate-400 hover:text-white transition">Security</a>
          <a href="/admin" className="text-slate-400 hover:text-[#00F2FE] transition">Admin Portal</a>
          <a href="/dashboard" className="px-4 py-2 rounded-lg bg-[#00F2FE] text-black font-semibold hover:bg-opacity-90 transition shadow-[0_0_20px_rgba(0,242,254,0.3)]">
            Launch Dashboard
          </a>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="relative pt-24 pb-20 px-6 max-w-7xl mx-auto text-center overflow-hidden">
        {/* Glowing Ambient Background */}
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[300px] bg-gradient-to-tr from-[#00F2FE]/20 via-[#A855F7]/20 to-transparent blur-[120px] rounded-full pointer-events-none" />

        <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full border border-[#00F2FE]/30 bg-[#00F2FE]/10 text-[#00F2FE] text-xs font-semibold mb-8">
          <Zap className="w-3.5 h-3.5" />
          <span>PRODUCTION-READY 9-ENGINE ARCHITECTURE</span>
        </div>

        <h1 className="text-5xl md:text-7xl font-extrabold tracking-tight max-w-5xl mx-auto leading-tight mb-8">
          Build Enterprise-Grade <br />
          <span className="bg-clip-text text-transparent bg-gradient-to-r from-[#00F2FE] via-[#10B981] to-[#A855F7]">
            Data Cleaning & Risk Pipelines
          </span>
        </h1>

        <p className="text-slate-400 text-lg md:text-xl max-w-3xl mx-auto mb-10 leading-relaxed">
          Zero-Trust, ReDoS-Safe, and Tamper-Evident Data Processing Pipeline. Process, deduplicate, format global phones, verify MX records, and score risk in real-time.
        </p>

        <div className="flex items-center justify-center space-x-4 mb-16">
          <a href="/dashboard" className="px-8 py-4 rounded-xl bg-[#00F2FE] text-black font-bold flex items-center space-x-2 hover:shadow-[0_0_30px_rgba(0,242,254,0.5)] transition-all">
            <span>Start Processing Data</span>
            <ArrowRight className="w-5 h-5" />
          </a>
        </div>

        {/* Live Performance Stats Bar */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 max-w-4xl mx-auto border border-white/10 rounded-2xl bg-[#0B0F19]/80 backdrop-blur-md p-6">
          <div className="text-center">
            <div className="text-3xl font-bold text-[#00F2FE]">20,000</div>
            <div className="text-xs text-slate-400 mt-1">Max Batch Capacity</div>
          </div>
          <div className="text-center">
            <div className="text-3xl font-bold text-[#10B981]">9 Core</div>
            <div className="text-xs text-slate-400 mt-1">Fault-Tolerant Engines</div>
          </div>
          <div className="text-center">
            <div className="text-3xl font-bold text-[#A855F7]">SHA-256</div>
            <div className="text-xs text-slate-400 mt-1">Merkle Root Audit Chains</div>
          </div>
          <div className="text-center">
            <div className="text-3xl font-bold text-white">0% Loss</div>
            <div className="text-xs text-slate-400 mt-1">DLQ Reconciliation</div>
          </div>
        </div>
      </section>

      {/* 9-Engine Architecture Section */}
      <section id="engines" className="py-20 px-6 max-w-7xl mx-auto">
        <div className="text-center mb-16">
          <h2 className="text-3xl font-bold mb-4">Core Pipeline Engines</h2>
          <p className="text-slate-400 max-w-xl mx-auto text-sm">
            Two-tier fault isolation ensuring every single record ends up strictly accounted for in clean output or Dead Letter Queue.
          </p>
        </div>

        <div className="grid md:grid-cols-3 gap-6">
          {[
            { id: "01", name: "Normalization & Diacritics", desc: "Unicode NFKC normalization, address cleaning, diacritic stripping, and strict email/name parsing." },
            { id: "02", name: "HMAC Deduplication", desc: "Tenant-scoped HMAC-SHA256 fingerprinting for high-speed cross-record exact deduplication." },
            { id: "03", name: "Deep Email & MX Probe", desc: "2.0s async timeout MX record checks, SSRF-blocked DNS queries, disposable & role filters." },
            { id: "04", name: "Global Phone E.164", desc: "Google Libphonenumber carrier intelligence, E.164 formatting, and VoIP risk detection." },
            { id: "05", name: "Threat Rating (0-100)", desc: "Tokenized bot heuristics, spam trap detection, and 20 industry B2B sector classifications." },
            { id: "06", name: "Dynamic AST Rules", desc: "Zero-RCE safe Abstract Syntax Tree parser with ReDoS linter for tenant-specific rules." },
            { id: "07", name: "Resilience & Throttling", desc: "Bounded Token Buckets, half-open Circuit Breakers, and backpressure queue management." },
            { id: "08", name: "Merkle Compliance Chain", desc: "GDPR/CCPA PII redaction and tamper-evident SHA-256 Merkle root audit log chaining." },
            { id: "09", name: "Master Orchestrator & DLQ", desc: "Two-tier per-record & batch isolation with complete reconciliation audit reports." },
          ].map((engine) => (
            <div key={engine.id} className="p-6 rounded-2xl bg-[#0B0F19] border border-white/10 hover:border-[#00F2FE]/50 transition-all group">
              <div className="flex items-center justify-between mb-4">
                <span className="text-xs font-mono font-bold px-2 py-1 rounded bg-[#00F2FE]/10 text-[#00F2FE]">ENGINE {engine.id}</span>
                <CheckCircle2 className="w-4 h-4 text-[#10B981] opacity-0 group-hover:opacity-100 transition" />
              </div>
              <h3 className="text-lg font-bold mb-2 group-hover:text-[#00F2FE] transition">{engine.name}</h3>
              <p className="text-slate-400 text-sm leading-relaxed">{engine.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Security & Compliance Badges */}
      <section id="security" className="py-16 px-6 border-t border-white/10 bg-[#0B0F19]/50">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-8">
          <div className="max-w-xl">
            <h2 className="text-2xl font-bold mb-3 flex items-center gap-2">
              <ShieldCheck className="text-[#10B981]" /> Zero-Trust Security Guarantees
            </h2>
            <p className="text-slate-400 text-sm leading-relaxed">
              Engineered with server pepper isolation, SSRF defenses on external lookups, ReDoS linting on regular expressions, and cryptographic audit hash tips.
            </p>
          </div>
          <div className="flex flex-wrap gap-3">
            <span className="px-4 py-2 rounded-xl border border-white/10 bg-[#080C14] text-xs font-mono text-slate-300">ReDoS-Safe Regex</span>
            <span className="px-4 py-2 rounded-xl border border-white/10 bg-[#080C14] text-xs font-mono text-slate-300">SSRF Blocked DNS</span>
            <span className="px-4 py-2 rounded-xl border border-white/10 bg-[#080C14] text-xs font-mono text-slate-300">GDPR Redaction</span>
            <span className="px-4 py-2 rounded-xl border border-white/10 bg-[#080C14] text-xs font-mono text-slate-300">Isolated Tenant Crypto</span>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="py-8 px-6 border-t border-white/10 text-center text-xs text-slate-500">
        © 2026 AMG DataOps Cloud. All rights reserved. Built for enterprise data processing.
      </footer>

    </div>
  );
}
