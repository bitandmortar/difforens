'use client';

import React, { useState, useMemo, useEffect, useRef } from 'react';
import * as duckdb from '@duckdb/duckdb-wasm';
import { useDuckDB } from '../hooks/use-duckdb';
import { useVirtualizer } from '@tanstack/react-virtual';
import { FORENSIC_SCRIPT } from '../lib/forensic-script';
import { Terminal, Download, Copy, Play, Search, ShieldAlert, FolderTree, DatabaseZap, CheckCircle2, BarChart4, FileOutput, ServerCog, Layers, Hash, AlertTriangle, FileText, Globe, Activity, Lock, ShieldCheck, FileDigit, GripVertical } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { Panel, Group as PanelGroup, Separator as PanelResizeHandle } from 'react-resizable-panels';
import { Treemap, ResponsiveContainer, Tooltip, BarChart, Bar, XAxis, YAxis, CartesianGrid, Cell, ScatterChart, Scatter, ZAxis, PieChart, Pie, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar, Legend } from 'recharts';

const formatBytes = (bytes: number) => {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};

export default function ForensicScannerUI() {
  const { db, isLoading: isDbLoading } = useDuckDB();
  const [reportA, setReportA] = useState<any>(null);
  const [reportB, setReportB] = useState<any>(null);
  const [diffResults, setDiffResults] = useState<any>(null);
  const [uploadTarget, setUploadTarget] = useState<'a' | 'b'>('a');
  const activeReport = uploadTarget === 'a' ? reportA : reportB;
  
  const [activeTab, setActiveTab] = useState<'script' | 'viewer' | 'diff' | 'about'>('script');
  const [copied, setCopied] = useState(false);
  const [viewerMode, setViewerMode] = useState<'overview' | 'files' | 'dupes'>('overview');
  const [searchQuery, setSearchQuery] = useState('');
  const [isProcessing, setIsProcessing] = useState(false);
  const [selectedFile, setSelectedFile] = useState<any>(null);
  
  const [duckDbFiles, setDuckDbFiles] = useState<any[]>([]);
  const [duckDbDupes, setDuckDbDupes] = useState<any[]>([]);

  // Effect for searching files in DuckDB
  useEffect(() => {
    if (!db || activeReport?.isParquet !== true) return;
    let isActive = true;
    const searchFiles = async () => {
      const conn = await db.connect();
      try {
        let query = `SELECT * FROM read_parquet('target.parquet')`;
        if (searchQuery) {
            const q = searchQuery.replace(/'/g, "''").toLowerCase();
            query += ` WHERE lower(path) LIKE '%${q}%' OR lower(sha256) LIKE '%${q}%' OR lower(lang) LIKE '%${q}%'`;
        }
        query += ` LIMIT 50000`;
        const result = await conn.query(query);
        if (isActive) setDuckDbFiles(result.toArray() as any);
      } catch(err){ console.error("Search query error", err) }
      finally { await conn.close(); }
    };
    searchFiles();
    return () => { isActive = false; };
  }, [db, activeReport, searchQuery]);

  // Effect for initializing Dupes in DuckDB
  useEffect(() => {
    if (!db || activeReport?.isParquet !== true) return;
    let isActive = true;
    const loadDupes = async () => {
       const conn = await db.connect();
       try {
         const query = `
           SELECT sha256 as hash, 
                  COUNT(*) as copies, 
                  MAX(size) as file_size,
                  ((COUNT(*) - 1) * MAX(size)) as wasted,
                  list(path) as paths,
                  list(modified) as modified_dates
           FROM read_parquet('target.parquet')
           WHERE sha256 IS NOT NULL AND sha256 != 'SKIPPED_LARGE_FILE' AND sha256 != 'HASH_ERROR'
           GROUP BY sha256
           HAVING COUNT(*) > 1
           ORDER BY wasted DESC
         `;
         const res = await conn.query(query);
         if (isActive) {
            // Need to map the flat results manually to array of arrays to match standard duplicate group format: [hash, files[]]
            const parsedDupes = res.toArray().map((row: any) => {
               // row.paths and row.modified_dates are apache arrow lists
               const rowPaths = row.paths?.toArray() || [];
               const rowMod = row.modified_dates?.toArray() || [];
               const files = rowPaths.map((p: string, idx: number) => ({
                   path: p,
                   modified: rowMod[idx] * 1000, // DuckDB handles parquet timestamps, assume seconds or raw
                   size: row.file_size
               }));
               return [row.hash, files];
            });
            setDuckDbDupes(parsedDupes);
         }
       } catch(err){ console.error("Load dupes error", err) }
       finally { await conn.close(); }
    }
    loadDupes();
    return () => { isActive = false; };
  }, [db, activeReport]);


  const handleCopy = () => {
    navigator.clipboard.writeText(FORENSIC_SCRIPT);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const blob = new Blob([FORENSIC_SCRIPT], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'forensic_scan.py';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (file.name.endsWith('.parquet')) {
      if (!db) {
         alert("DuckDB is still loading, please wait...");
         return;
      }
      setIsProcessing(true);
      try {
        await db.registerFileHandle('target.parquet', file, duckdb.DuckDBDataProtocol.BROWSER_FILEREADER, true);
        const conn = await db.connect();
        
        const countRes = await conn.query(`SELECT COUNT(*) as num_files, COALESCE(SUM(size), 0) as total_size FROM read_parquet('target.parquet')`);
        let num_files = 0;
        let total_size = 0;
        const countRows = countRes.toArray();
        if(countRows.length > 0) {
            num_files = Number(countRows[0].num_files || 0);
            total_size = Number(countRows[0].total_size || 0);
        }

        const langRes = await conn.query(`SELECT lang, COUNT(*) as count, SUM(size) as total_size_bytes FROM read_parquet('target.parquet') WHERE lang IS NOT NULL GROUP BY lang`);
        const file_type_statistics: any = {};
        langRes.toArray().forEach((row: any) => {
           file_type_statistics[row.lang] = { count: Number(row.count), total_size_bytes: Number(row.total_size_bytes) };
        });
        
        const reportObj = {
          isParquet: true,
          metadata: {
             volume_name: file.name,
             total_files: num_files,
             total_size: total_size,
             file_type_statistics,
             root_path: "Extracted via Parquet metadata",
             hostname: "Native",
             platform: "DuckDB"
          },
          errors: []
        };
        if (uploadTarget === 'a') setReportA(reportObj);
        else setReportB(reportObj);
        setActiveTab('viewer');
        setIsProcessing(false);
        await conn.close();
      } catch(err) {
        alert("Error reading parquet: " + err);
        setIsProcessing(false);
      }
      return;
    }

    // JSON Handler fallback
    setIsProcessing(true);
    const worker = new Worker('/worker.js');
    
    worker.onmessage = (event) => {
      const { type, payload, error } = event.data;
      if (type === 'PROCESS_REPORT_SUCCESS') {
        if (uploadTarget === 'a') setReportA(payload);
        else setReportB(payload);
        
        setActiveTab('viewer');
        setIsProcessing(false);
        worker.terminate();
      } else if (type === 'PROCESS_REPORT_ERROR') {
        alert("Invalid Forensic JSON report file: " + error);
        setIsProcessing(false);
        worker.terminate();
      }
    };

    const reader = new FileReader();
    reader.onload = (event) => {
      worker.postMessage({ type: 'PROCESS_REPORT', payload: { text: event.target?.result } });
    };
    reader.readAsText(file);
  };

  const handleComputeDiff = () => {
    if (!reportA || !reportB) return;
    setIsProcessing(true);
    const worker = new Worker('/worker.js');
    
    worker.onmessage = (event) => {
      const { type, payload, error } = event.data;
      if (type === 'COMPUTE_DIFF_SUCCESS') {
        setDiffResults(payload);
        setActiveTab('diff');
        setIsProcessing(false);
        worker.terminate();
      } else if (type === 'COMPUTE_DIFF_ERROR') {
        alert("Diff Error: " + error);
        setIsProcessing(false);
        worker.terminate();
      }
    };

    worker.postMessage({ 
      type: 'COMPUTE_DIFF', 
      payload: { 
        filesA: reportA.files || [], 
        filesB: reportB.files || [] 
      } 
    });
  };


  // Compute duplicate files based on SHA256
  const dupes = useMemo(() => {
    if (!activeReport?.files) return [];
    const groups: Record<string, any[]> = {};
    activeReport.files.forEach((f: any) => {
      if (f.sha256 && f.sha256 !== 'SKIPPED_LARGE_FILE' && f.sha256 !== 'HASH_ERROR') {
        if (!groups[f.sha256]) groups[f.sha256] = [];
        groups[f.sha256].push(f);
      }
    });
    
    // Filter to actual duplicates and sort by wasted space
    return Object.entries(groups)
      .filter(([_, files]) => files.length > 1)
      .sort((a,b) => {
        const wastedA = a[1][0].size * (a[1].length - 1);
        const wastedB = b[1][0].size * (b[1].length - 1);
        return wastedB - wastedA;
      });
  }, [activeReport]);

  const filteredFiles = useMemo(() => {
    if (!activeReport?.files) return [];
    let f = activeReport.files;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      f = f.filter((file: any) =>
        (file.path && file.path.toLowerCase().includes(q)) ||
        (file.sha256 && file.sha256.toLowerCase().includes(q)) ||
        (file.lang && file.lang.toLowerCase().includes(q))
      );
    }
    return f;
  }, [activeReport, searchQuery]);

  const activeFiles = activeReport?.isParquet ? duckDbFiles : filteredFiles;
  const activeDupes = activeReport?.isParquet ? duckDbDupes : dupes;

  const filesParentRef = useRef<HTMLDivElement>(null);
  const rowVirtualizer = useVirtualizer({
    count: activeFiles.length,
    getScrollElement: () => filesParentRef.current,
    estimateSize: () => 78,
    overscan: 10,
  });

  const dupesParentRef = useRef<HTMLDivElement>(null);
  const dupesVirtualizer = useVirtualizer({
    count: activeDupes.length,
    getScrollElement: () => dupesParentRef.current,
    estimateSize: () => 140, // Height is variable since it shows children paths, but we can estimate
    overscan: 5,
  });

  const chartData = useMemo(() => {
    if (!activeReport?.metadata?.file_type_statistics) return [];
    return Object.entries(activeReport.metadata.file_type_statistics)
      .map(([lang, stats]: any) => ({
        name: lang,
        size: stats.total_size_bytes,
        count: stats.count
      }))
      .sort((a, b) => b.size - a.size);
  }, [activeReport]);

  const COLORS = ['#8884d8', '#8dd1e1', '#82ca9d', '#a4de6c', '#d0ed57', '#ffc658', '#ff7300', '#d0ed57', '#a4de6c'];

  const scatterData = useMemo(() => {
    return activeFiles
      .filter((f: any) => f.entropy !== null && f.size > 0)
      .slice(0, 500)
      .map((f: any) => ({
        name: f.filename,
        size: f.size,
        entropy: f.entropy,
        lang: f.lang || 'Unknown'
      }));
  }, [activeFiles]);

  const pieData = useMemo(() => {
    const wasted = activeDupes.reduce((acc, val) => acc + (val[1][0].size * (val[1].length - 1)), 0);
    // Find sum of all files sizes
    let totalSize = 0;
    if (activeReport?.metadata?.total_size_bytes) {
      totalSize = activeReport.metadata.total_size_bytes;
    } else {
      totalSize = activeFiles.reduce((acc: number, val: any) => acc + (val.size || 0), 0);
    }
    const unique = Math.max(totalSize - wasted, 0);
    return [
      { name: 'Unique Content', value: unique, fill: '#10b981' }, // teal
      { name: 'Duplicated / Wasted Space', value: wasted, fill: '#ef4444' } // red
    ];
  }, [activeDupes, activeFiles, activeReport]);
  
  const radarData = useMemo(() => {
    if (!activeReport?.metadata?.file_type_statistics) return [];
    
    const stats = Object.entries(activeReport.metadata.file_type_statistics)
      .map(([lang, s]: any) => ({
        lang,
        size: s.total_size_bytes,
        count: s.count,
        avgSize: s.total_size_bytes / (s.count || 1)
      }))
      .filter(s => s.lang !== 'Unknown') // Ignore unknown
      .sort((a, b) => b.size - a.size)
      .slice(0, 6); // Top 6 languages
      
    // Radar charts look better when values are normalized to a common scale
    const maxSize = Math.max(...stats.map(s => s.size), 1);
    const maxCount = Math.max(...stats.map(s => s.count), 1);
    const maxAvgSize = Math.max(...stats.map(s => s.avgSize), 1);
    
    return stats.map(s => ({
      subject: s.lang,
      sizeNorm: (s.size / maxSize) * 100,
      countNorm: (s.count / maxCount) * 100,
      avgSizeNorm: (s.avgSize / maxAvgSize) * 100,
      fullMark: 100,
    }));
  }, [activeReport]);

  return (
    <div className="min-h-screen bg-[#0A0A0A] text-[#E0E0E0] selection:bg-[#333333] selection:text-white font-sans antialiased flex flex-col">
      {/* Header */}
      <header className="border-b border-[#222] bg-[#111]/80 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="bg-[#1A1A1A] p-2 rounded-lg border border-[#333]">
              <Terminal className="w-5 h-5 text-gray-300" />
            </div>
            <div>
              <h1 className="text-xl font-medium tracking-tight text-white flex items-center gap-2">
                Forensic Scanner <span className="text-xs px-2 py-0.5 rounded-full bg-[#222] text-gray-400 font-mono tracking-widest border border-[#333]">OSX TAHOE</span>
              </h1>
            </div>
          </div>
          <nav className="flex gap-2 bg-[#1A1A1A] p-1 rounded-xl border border-[#222]">
            {(['script', 'viewer', 'diff', 'about'] as const).map(tab => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                disabled={tab === 'diff' && !diffResults}
                className={`text-sm px-4 py-1.5 rounded-lg capitalize transition-all ${
                  activeTab === tab ? 'bg-[#333] text-white shadow-sm' : 
                  (tab === 'diff' && !diffResults) ? 'text-gray-600 cursor-not-allowed' : 'text-gray-400 hover:text-white hover:bg-[#222]'
                }`}
              >
                {tab}
              </button>
            ))}
          </nav>
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-6 md:p-8 flex flex-col gap-8">
        
        {/* SCRIPT TAB */}
        {activeTab === 'script' && (
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="flex flex-col gap-8">
            <div className="grid lg:grid-cols-3 gap-8">
              <div className="lg:col-span-2 flex flex-col gap-4">
                <div className="flex items-center justify-between">
                  <h2 className="text-lg font-medium text-white flex items-center gap-2">
                    <ServerCog className="w-5 h-5" />
                    Python Deployment Script
                  </h2>
                  <div className="flex gap-3">
                    <button onClick={handleCopy} className="flex items-center gap-2 text-xs font-medium bg-[#1A1A1A] hover:bg-[#2A2A2A] border border-[#333] px-3 py-1.5 rounded-md transition-colors text-white">
                      {copied ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      {copied ? 'Copied' : 'Copy Code'}
                    </button>
                    <button onClick={handleDownload} className="flex items-center gap-2 text-xs font-medium bg-white text-black hover:bg-gray-200 px-3 py-1.5 rounded-md transition-colors">
                      <Download className="w-3.5 h-3.5" />
                      Download .py
                    </button>
                  </div>
                </div>
                <div className="relative group">
                  <div className="absolute -inset-0.5 bg-gradient-to-br from-[#333] to-[#111] rounded-xl blur opacity-20 group-hover:opacity-40 transition duration-500"></div>
                  <pre className="relative p-6 rounded-xl bg-[#0F0F0F] border border-[#222] font-mono text-[13px] leading-relaxed text-gray-300 overflow-x-auto shadow-2xl max-h-[600px] styled-scrollbar">
                    <code>{FORENSIC_SCRIPT}</code>
                  </pre>
                </div>
              </div>

              <div className="flex flex-col gap-6">
                <div className="bg-[#141414] border border-[#222] rounded-xl p-6">
                  <h3 className="text-sm font-semibold text-white mb-4 uppercase tracking-wider flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 text-orange-400" />
                    Forensic Soundness
                  </h3>
                  <ul className="space-y-4 text-sm text-gray-400">
                    <li className="flex gap-3 items-start">
                      <DatabaseZap className="w-4 h-4 mt-0.5 text-gray-500 shrink-0" />
                      <p><strong className="text-gray-200">Zero Spotlight Dependency:</strong> Uses POSIX system calls (<code className="text-xs bg-[#222] px-1 rounded text-orange-200">os.lstat</code>) avoiding \`mds\`/\`mdfind\` pitfalls.</p>
                    </li>
                    <li className="flex gap-3 items-start">
                      <Hash className="w-4 h-4 mt-0.5 text-gray-500 shrink-0" />
                      <p><strong className="text-gray-200">Content Addressing:</strong> Computes SHA256 hashes and verifies Shannon Entropy on files to identify dupes/packed files.</p>
                    </li>
                  </ul>
                </div>

                <div className="bg-[#141414] border border-[#222] rounded-xl p-6">
                  <h3 className="text-sm font-semibold text-white mb-4 uppercase tracking-wider flex items-center gap-2">
                    <Play className="w-4 h-4 text-emerald-400" />
                    Usage
                  </h3>
                  <div className="space-y-4">
                    <div className="bg-black border border-[#222] rounded-lg p-3 font-mono text-xs text-gray-300">
                      chmod +x forensic_scan.py<br/>
                      ./forensic_scan.py /Path/Target VolumeName --entropy --parquet
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </motion.div>
        )}

        {/* VIEWER TAB */}
        {activeTab === 'viewer' && (
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="flex flex-col gap-6 h-full">
            <div className="flex items-center justify-between gap-4 bg-[#141414] p-4 rounded-xl border border-[#222]">
                <div className="flex gap-2">
                    <button 
                        onClick={() => setUploadTarget('a')} 
                        className={`px-4 py-2 text-xs rounded-lg border transition ${uploadTarget === 'a' ? 'bg-[#333] border-white text-white' : 'bg-[#0A0A0A] border-[#222] text-gray-500'}`}
                    >
                        Baseline (Report A) {reportA ? '✓' : ''}
                    </button>
                    <button 
                        onClick={() => setUploadTarget('b')} 
                        className={`px-4 py-2 text-xs rounded-lg border transition ${uploadTarget === 'b' ? 'bg-[#333] border-white text-white' : 'bg-[#0A0A0A] border-[#222] text-gray-500'}`}
                    >
                        Target (Report B) {reportB ? '✓' : ''}
                    </button>
                </div>
                {reportA && reportB && (
                    <button 
                        onClick={handleComputeDiff}
                        className="bg-emerald-500 hover:bg-emerald-600 text-black font-bold px-4 py-2 rounded-lg text-xs transition flex items-center gap-2"
                    >
                        <Activity className="w-4 h-4"/> Compute Multi-Diff
                    </button>
                )}
            </div>

            {!activeReport ? (
              <div className="flex flex-col items-center justify-center py-32 border border-dashed border-[#333] rounded-2xl bg-[#141414]">
                <div className="p-4 bg-[#1A1A1A] rounded-full border border-[#222] mb-6">
                  <FileOutput className="w-8 h-8 text-gray-400" />
                </div>
                <h2 className="text-xl font-medium text-white mb-2">Upload Report {uploadTarget.toUpperCase()}</h2>
                <p className="text-gray-500 text-sm mb-8 max-w-sm text-center">Load the JSON artifact for the {uploadTarget === 'a' ? 'baseline' : 'target'} state to enable comparison.</p>
                {isProcessing ? (
                  <div className="flex items-center gap-3 text-emerald-400 font-mono text-sm">
                    <Activity className="w-4 h-4 animate-pulse" /> Parsing Payload via Worker...
                  </div>
                ) : (
                  <label className="cursor-pointer bg-white text-black px-6 py-2.5 rounded-lg font-medium text-sm hover:bg-gray-200 transition-colors">
                    Select JSON Report
                    <input type="file" accept=".json" onChange={handleFileUpload} className="hidden" />
                  </label>
                )}
              </div>
            ) : (
              <div className="flex flex-col gap-6 h-full">
                {/* Meta Overview */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                   <div className="bg-[#141414] border border-[#222] p-5 rounded-xl">
                    <p className="text-xs text-gray-500 mb-1 uppercase tracking-wider">Volume</p>
                    <p className="text-sm font-mono text-white truncate">{activeReport.metadata.volume_name}</p>
                  </div>
                  <div className="bg-[#141414] border border-[#222] p-5 rounded-xl">
                    <p className="text-xs text-gray-500 mb-1 uppercase tracking-wider">Total Scanned Size</p>
                    <p className="text-sm font-bold text-white">{formatBytes(activeReport.metadata.total_size)}</p>
                  </div>
                  <div className="bg-[#141414] border border-[#222] p-5 rounded-xl">
                    <p className="text-xs text-gray-500 mb-1 uppercase tracking-wider">Total Files</p>
                    <p className="text-sm text-white">{activeReport.metadata.total_files?.toLocaleString()}</p>
                  </div>
                  <div className="bg-[#141414] border border-[#222] p-5 rounded-xl flex justify-between items-center">
                    <div>
                      <p className="text-xs text-gray-500 mb-1 uppercase tracking-wider">Duplicate Groups</p>
                      <p className="text-sm text-orange-400 font-bold">{dupes.length.toLocaleString()}</p>
                    </div>
                    <button onClick={() => { if(uploadTarget === 'a') setReportA(null); else setReportB(null); }} className="text-xs text-red-400 border border-red-500/30 hover:bg-red-500/10 px-3 py-1 rounded">Close</button>
                  </div>
                </div>

                {/* Sub-Tabs */}
                <div className="flex items-center gap-2 border-b border-[#333] pb-2">
                  <button onClick={() => setViewerMode('overview')} className={`px-4 py-2 text-sm rounded-t-lg transition ${viewerMode === 'overview' ? 'text-white border-b-2 border-white' : 'text-gray-500 hover:text-gray-300'}`}>Overview</button>
                  <button onClick={() => setViewerMode('files')} className={`px-4 py-2 text-sm rounded-t-lg transition ${viewerMode === 'files' ? 'text-white border-b-2 border-white' : 'text-gray-500 hover:text-gray-300'}`}>All Files & Search</button>
                  <button onClick={() => setViewerMode('dupes')} className={`flex items-center gap-2 px-4 py-2 text-sm rounded-t-lg transition ${viewerMode === 'dupes' ? 'text-orange-400 border-b-2 border-orange-400' : 'text-gray-500 hover:text-orange-300'}`}>
                    <Layers className="w-4 h-4"/> 
                    Duplicates 
                    <span className="bg-[#222] text-xs px-2 rounded-full">{dupes.length}</span>
                  </button>
                </div>

                <div className="bg-[#0F0F0F] border border-[#222] rounded-xl overflow-hidden flex flex-col flex-1 min-h-[500px]">
                  
                  {/* OVERVIEW MODE */}
                  {viewerMode === 'overview' && (
                    <div className="p-6 flex flex-col gap-6 overflow-auto">
                      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                        {/* Treemap */}
                        <div className="bg-[#141414] border border-[#222] rounded-xl p-5 flex flex-col">
                          <h3 className="text-sm font-medium text-white mb-4 uppercase tracking-wider border-b border-[#333] pb-2">Language Size Distribution (Treemap)</h3>
                          <div className="h-64 w-full flex-1">
                            <ResponsiveContainer width="100%" height="100%">
                              <Treemap
                                data={chartData}
                                dataKey="size"
                                aspectRatio={4 / 3}
                                stroke="#141414"
                                fill="#8884d8"
                              >
                                <Tooltip
                                  formatter={(value: any) => formatBytes(value as number)}
                                  contentStyle={{ backgroundColor: '#1A1A1A', borderColor: '#333', color: '#E0E0E0' }}
                                />
                              </Treemap>
                            </ResponsiveContainer>
                          </div>
                        </div>

                        {/* Bar Chart */}
                        <div className="bg-[#141414] border border-[#222] rounded-xl p-5 flex flex-col">
                          <h3 className="text-sm font-medium text-white mb-4 uppercase tracking-wider border-b border-[#333] pb-2">File Count by Language (Bar Chart)</h3>
                          <div className="flex-1 min-h-[250px] w-full mt-2">
                            <ResponsiveContainer width="100%" height="100%">
                              <BarChart data={chartData.slice(0, 10)} layout="vertical" margin={{ top: 0, right: 30, left: 20, bottom: 0 }}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#333" horizontal={false} />
                                <XAxis type="number" stroke="#666" />
                                <YAxis dataKey="name" type="category" stroke="#888" width={80} tick={{ fontSize: 12, fill: '#aaa' }} />
                                <Tooltip 
                                  cursor={{ fill: '#222' }}
                                  contentStyle={{ backgroundColor: '#1A1A1A', borderColor: '#333', color: '#E0E0E0' }} 
                                />
                                <Bar dataKey="count" fill="#4f46e5" radius={[0, 4, 4, 0]}>
                                  {chartData.slice(0, 10).map((entry, index) => (
                                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                                  ))}
                                </Bar>
                              </BarChart>
                            </ResponsiveContainer>
                          </div>
                        </div>

                        {/* Scatter Plot */}
                        <div className="bg-[#141414] border border-[#222] rounded-xl p-5 flex flex-col">
                          <h3 className="text-sm font-medium text-white mb-4 uppercase tracking-wider border-b border-[#333] pb-2">Size vs Entropy (Scatter Plot)</h3>
                          <div className="flex-1 min-h-[250px] w-full mt-2">
                            <ResponsiveContainer width="100%" height="100%">
                              <ScatterChart margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                                <XAxis type="number" dataKey="size" name="Size" stroke="#666" tickFormatter={(v) => formatBytes(v)} />
                                <YAxis type="number" dataKey="entropy" name="Entropy" stroke="#666" domain={[0, 8]} />
                                <ZAxis type="category" dataKey="lang" name="Language" />
                                <Tooltip 
                                  cursor={{ strokeDasharray: '3 3' }}
                                  contentStyle={{ backgroundColor: '#1A1A1A', borderColor: '#333', color: '#E0E0E0' }}
                                  formatter={(value: any, name: any) => name === 'Size' ? formatBytes(value) : (name === 'Entropy' ? Number(value).toFixed(2) : value)}
                                />
                                <Scatter data={scatterData} fill="#f59e0b" />
                              </ScatterChart>
                            </ResponsiveContainer>
                          </div>
                        </div>

                        {/* Pie Chart */}
                        <div className="bg-[#141414] border border-[#222] rounded-xl p-5 flex flex-col">
                          <h3 className="text-sm font-medium text-white mb-4 uppercase tracking-wider border-b border-[#333] pb-2">Space Efficiency (Pie Chart)</h3>
                          <div className="flex-1 min-h-[250px] w-full mt-2">
                            <ResponsiveContainer width="100%" height="100%">
                              <PieChart>
                                <Pie
                                  data={pieData}
                                  cx="50%"
                                  cy="50%"
                                  innerRadius={60}
                                  outerRadius={80}
                                  paddingAngle={5}
                                  dataKey="value"
                                  stroke="none"
                                >
                                  {pieData.map((entry, index) => (
                                    <Cell key={`cell-${index}`} fill={entry.fill} />
                                  ))}
                                </Pie>
                                <Tooltip 
                                  formatter={(value: any) => formatBytes(value as number)}
                                  contentStyle={{ backgroundColor: '#1A1A1A', borderColor: '#333', color: '#E0E0E0' }} 
                                />
                                <Legend verticalAlign="bottom" height={36} wrapperStyle={{ fontSize: '12px', color: '#aaa' }}/>
                              </PieChart>
                            </ResponsiveContainer>
                          </div>
                        </div>

                        {/* Radar Chart */}
                        <div className="bg-[#141414] border border-[#222] rounded-xl p-5 flex flex-col">
                          <h3 className="text-sm font-medium text-white mb-4 uppercase tracking-wider border-b border-[#333] pb-2">Language Profiler (Radar Chart)</h3>
                          <div className="flex-1 min-h-[250px] w-full mt-2">
                            <ResponsiveContainer width="100%" height="100%">
                              <RadarChart cx="50%" cy="50%" outerRadius="70%" data={radarData}>
                                <PolarGrid stroke="#333" />
                                <PolarAngleAxis dataKey="subject" tick={{ fill: '#888', fontSize: 10 }} />
                                <PolarRadiusAxis angle={30} domain={[0, 100]} tick={false} axisLine={false} />
                                <Radar name="Total Size" dataKey="sizeNorm" stroke="#8884d8" fill="#8884d8" fillOpacity={0.3} />
                                <Radar name="File Count" dataKey="countNorm" stroke="#82ca9d" fill="#82ca9d" fillOpacity={0.3} />
                                <Tooltip 
                                  formatter={(value: any, name: any, props: any) => {
                                    const lang = props.payload.subject;
                                    const actualData = chartData.find(c => c.name === lang);
                                    if (!actualData) return [value, name];
                                    if (name === 'Total Size') return [formatBytes(actualData.size), name];
                                    if (name === 'File Count') return [actualData.count, name];
                                    return [value, name];
                                  }}
                                  contentStyle={{ backgroundColor: '#1A1A1A', borderColor: '#333', color: '#E0E0E0' }} 
                                />
                                <Legend wrapperStyle={{ fontSize: '12px' }} />
                              </RadarChart>
                            </ResponsiveContainer>
                          </div>
                        </div>

                         {/* Scan Details */}
                        <div className="bg-[#141414] border border-[#222] rounded-xl p-5 flex flex-col">
                          <h3 className="text-sm font-medium text-white mb-4 uppercase tracking-wider border-b border-[#333] pb-2">Scan Details</h3>
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm mt-4">
                             <div>
                               <p className="text-gray-500 mb-1">Root Path</p>
                               <p className="text-gray-300 font-mono text-xs truncate" title={activeReport.metadata.root_path}>{activeReport.metadata.root_path}</p>
                             </div>
                             <div>
                               <p className="text-gray-500 mb-1">Hostname</p>
                               <p className="text-gray-300 font-mono text-xs">{activeReport.metadata.hostname}</p>
                             </div>
                             <div>
                               <p className="text-gray-500 mb-1">Platform</p>
                               <p className="text-gray-300 font-mono text-xs">{activeReport.metadata.platform}</p>
                             </div>
                             <div>
                               <p className="text-gray-500 mb-1">Errors</p>
                               <p className={`font-mono text-xs font-bold ${(activeReport.errors?.length || 0) > 0 ? 'text-red-400' : 'text-emerald-400'}`}>{activeReport.errors?.length || 0}</p>
                             </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* FILES MODE */}
                  {viewerMode === 'files' && (
                    <div className="flex flex-col h-full">
                      <div className="p-3 border-b border-[#222] bg-[#141414]">
                        <input 
                          type="text" 
                          placeholder="Search paths, hashes, or languages..." 
                          value={searchQuery}
                          onChange={(e) => setSearchQuery(e.target.value)}
                          className="w-full bg-[#0A0A0A] border border-[#333] rounded-lg px-4 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-blue-500"
                        />
                      </div>
                      <div className="flex-1 overflow-hidden">
                        <PanelGroup orientation="horizontal">
                          <Panel defaultSize={60} minSize={30}>
                            <div ref={filesParentRef} className="overflow-auto h-full p-4 relative">
                              <div
                                style={{
                                  height: `${rowVirtualizer.getTotalSize()}px`,
                                  width: '100%',
                                  position: 'relative',
                                }}
                              >
                                {rowVirtualizer.getVirtualItems().map((virtualRow) => {
                                  const file = activeFiles[virtualRow.index];
                                  return (
                                    <div 
                                      key={virtualRow.key} 
                                      style={{
                                        position: 'absolute',
                                        top: 0,
                                        left: 0,
                                        width: '100%',
                                        height: `${virtualRow.size}px`,
                                        transform: `translateY(${virtualRow.start}px)`,
                                        paddingBottom: '8px', 
                                      }}
                                    >
                                      <div
                                        onClick={() => setSelectedFile(file)}
                                        className={`flex flex-col h-full border rounded-lg p-3 cursor-pointer transition ${selectedFile?.id === file.id ? 'bg-[#1A1A1A] border-blue-500/50' : 'bg-[#161616] border-[#222] hover:bg-[#1A1A1A]'}`}>
                                        <div className="flex justify-between items-start mb-1">
                                          <span className="text-sm text-gray-200 font-medium truncate pr-4" title={file.filename}>{file.filename}</span>
                                          <span className="text-xs text-gray-500 whitespace-nowrap font-mono">{formatBytes(file.size)}</span>
                                        </div>
                                        <span className="text-xs text-gray-500 font-mono truncate mb-2">{file.path}</span>
                                        <div className="flex items-center gap-3 text-[10px]">
                                          {file.sha256 && <span className="flex items-center gap-1 text-blue-400/80"><Hash className="w-3 h-3"/> {file.sha256.slice(0,16)}...</span>}
                                          {file.entropy !== null && <span className={`flex items-center gap-1 ${file.entropy > 7.5 ? 'text-red-400' : file.entropy > 6 ? 'text-orange-400' : 'text-emerald-400'}`}><Activity className="w-3 h-3"/> {file.entropy.toFixed(3)}</span>}
                                          {file.lang && <span className="px-1.5 py-0.5 rounded bg-[#222] text-gray-400 border border-[#333]">{file.lang}</span>}
                                        </div>
                                      </div>
                                    </div>
                                  );
                                })}
                              </div>
                              {activeFiles.length === 50000 && <div className="text-center text-xs text-gray-500 py-4 absolute bottom-0 w-full">Displaying first 50,000 matches.</div>}
                              {activeFiles.length === 0 && <div className="text-center text-sm text-gray-500 py-12 absolute top-0 w-full">No files match your search.</div>}
                            </div>
                          </Panel>
                          
                          <PanelResizeHandle className="w-1 bg-[#222] hover:bg-[#444] transition flex items-center justify-center cursor-col-resize">
                            <div className="h-8 w-1 bg-[#444] rounded-full" />
                          </PanelResizeHandle>
                          
                          <Panel defaultSize={40} minSize={20}>
                            <div className="h-full bg-[#111] border-l border-[#222] p-4 flex flex-col">
                              {selectedFile ? (
                                <div className="flex flex-col gap-6 h-full">
                                  <div>
                                    <h3 className="text-white font-medium mb-1 truncate" title={selectedFile.filename}>{selectedFile.filename}</h3>
                                    <p className="text-xs text-gray-500 font-mono break-all">{selectedFile.path}</p>
                                  </div>
                                  
                                  <div className="grid grid-cols-2 gap-4">
                                    <div className="bg-[#1A1A1A] p-3 rounded-lg border border-[#333]">
                                      <p className="text-[10px] uppercase text-gray-500 mb-1">Created</p>
                                      <p className="text-xs text-gray-300">{selectedFile.created ? new Date(selectedFile.created).toLocaleString() : 'N/A'}</p>
                                    </div>
                                    <div className="bg-[#1A1A1A] p-3 rounded-lg border border-[#333]">
                                      <p className="text-[10px] uppercase text-gray-500 mb-1">Modified</p>
                                      <p className="text-xs text-gray-300">{selectedFile.modified ? new Date(selectedFile.modified).toLocaleString() : 'N/A'}</p>
                                    </div>
                                  </div>

                                  <div className="bg-[#1A1A1A] border border-[#333] rounded-lg p-4 space-y-4">
                                    <div className="flex items-center justify-between">
                                      <div className="flex items-center gap-2">
                                        <ShieldCheck className="w-4 h-4 text-emerald-400" />
                                        <span className="text-xs text-emerald-400 font-medium uppercase tracking-wider">Provenance Verified</span>
                                      </div>
                                      {selectedFile.entropy !== null && (
                                        <span className="text-xs font-mono text-gray-500" title="Shannon Entropy">ENTROPY: {selectedFile.entropy.toFixed(3)}</span>
                                      )}
                                    </div>
                                    <div className="space-y-1">
                                      <p className="text-[10px] uppercase text-gray-500">Cryptographic Hash (SHA-256)</p>
                                      <p className="text-xs font-mono text-gray-300 break-all bg-black p-2 rounded border border-[#222]">
                                        {selectedFile.sha256 || 'Not computed'}
                                      </p>
                                    </div>
                                  </div>

                                  <div className="flex-1 min-h-0 flex flex-col">
                                    <div className="flex items-center justify-between mb-2">
                                      <h4 className="text-xs text-gray-400 uppercase flex items-center gap-2">
                                        <FileDigit className="w-3.5 h-3.5" />
                                        Hex Dump Preview (Simulated)
                                      </h4>
                                    </div>
                                    <div className="flex-1 bg-black border border-[#333] rounded-lg p-3 overflow-auto font-mono text-[10px] leading-relaxed text-gray-400 styled-scrollbar">
                                      {Array.from({length: 16}).map((_, i) => (
                                        <div key={i} className="flex gap-4">
                                          <span className="text-blue-500/50">{(i*16).toString(16).padStart(8, '0')}</span>
                                          <span className="text-gray-300">
                                            {Array.from({length: 16}).map(() => Math.floor(Math.random() * 256).toString(16).padStart(2, '0')).join(' ')}
                                          </span>
                                          <span className="text-gray-500 hidden xl:block">
                                            {Array.from({length: 16}).map(() => {
                                              const c = Math.floor(Math.random() * 94) + 33;
                                              return String.fromCharCode(c);
                                            }).join('')}
                                          </span>
                                        </div>
                                      ))}
                                    </div>
                                  </div>
                                </div>
                              ) : (
                                <div className="h-full flex flex-col items-center justify-center text-gray-500 gap-3">
                                  <FolderTree className="w-8 h-8 opacity-50" />
                                  <p className="text-sm">Select a file to view forensic details.</p>
                                </div>
                              )}
                            </div>
                          </Panel>
                        </PanelGroup>
                      </div>
                    </div>
                  )}

                  {/* DUPES MODE */}
                  {viewerMode === 'dupes' && (
                    <div className="flex flex-col h-full bg-[#111]">
                      <div className="p-4 border-b border-[#222] bg-[#161616] flex justify-between items-center">
                        <div>
                          <h3 className="text-sm font-medium text-white">Identical File Clusters</h3>
                          <p className="text-xs text-gray-500">Groups of files sharing identical SHA256 hashes.</p>
                        </div>
                        <div className="text-right">
                          <p className="text-xs text-gray-500 uppercase">Wasted Space</p>
                          <p className="text-lg font-bold text-red-400">{formatBytes(activeDupes.reduce((acc, val) => acc + (val[1][0].size * (val[1].length - 1)), 0))}</p>
                        </div>
                      </div>
                      <div ref={dupesParentRef} className="flex-1 overflow-auto p-4 relative">
                        {activeDupes.length === 0 ? (
                          <div className="text-center text-gray-500 py-12 absolute top-0 w-full">No duplicate files found across the scanned target.</div>
                        ) : (
                          <div
                            style={{
                              height: `${dupesVirtualizer.getTotalSize()}px`,
                              width: '100%',
                              position: 'relative',
                            }}
                          >
                            {dupesVirtualizer.getVirtualItems().map((virtualRow) => {
                              const [hash, files] = activeDupes[virtualRow.index];
                              const wasted = files[0].size * (files.length - 1);
                              return (
                                <div 
                                  key={virtualRow.key}
                                  data-index={virtualRow.index}
                                  ref={dupesVirtualizer.measureElement}
                                  style={{
                                    position: 'absolute',
                                    top: 0,
                                    left: 0,
                                    width: '100%',
                                    transform: `translateY(${virtualRow.start}px)`,
                                    paddingBottom: '16px', // space-y-4 equivalent
                                  }}
                                >
                                  <div className="bg-[#1A1A1A] border border-[#333] rounded-xl overflow-hidden">
                                    <div className="bg-[#222] p-3 flex justify-between items-center border-b border-[#333]">
                                      <div className="flex items-center gap-3">
                                        <span className="text-xs font-bold bg-orange-500/20 text-orange-400 border border-orange-500/30 px-2 py-0.5 rounded uppercase">
                                          {files.length} Copies
                                        </span>
                                        <span className="text-xs font-mono text-gray-400 hidden md:block">{hash}</span>
                                      </div>
                                      <div className="flex items-center gap-3">
                                        <span className="text-xs text-gray-500">File Size: {formatBytes(files[0].size)}</span>
                                        <span className="text-xs font-bold text-red-400 bg-red-400/10 px-2 py-0.5 rounded">Wasted: {formatBytes(wasted)}</span>
                                      </div>
                                    </div>
                                    <div className="p-2 space-y-1 bg-[#141414]">
                                      {files.map((f: any, idx: number) => (
                                        <div key={idx} className="flex justify-between items-center px-3 py-1.5 hover:bg-[#222] rounded transition group">
                                          <span className="text-xs text-gray-400 font-mono truncate">{f.path}</span>
                                          <span className="text-xs text-gray-600 opacity-0 group-hover:opacity-100 transition whitespace-nowrap ml-4">Modified: {new Date(f.modified).toLocaleDateString()}</span>
                                        </div>
                                      ))}
                                    </div>
                                  </div>
                                </div>
                              );
                            })}
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}
          </motion.div>
        )}

        {/* DIFF TAB */}
        {activeTab === 'diff' && diffResults && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="flex flex-col gap-6">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <div className="bg-[#141414] border border-[#222] rounded-xl p-6 border-l-4 border-l-emerald-500">
                        <div className="flex justify-between items-center mb-2">
                            <h3 className="text-xs font-bold text-emerald-400 uppercase tracking-widest">Added</h3>
                            <CheckCircle2 className="w-4 h-4 text-emerald-500" />
                        </div>
                        <p className="text-2xl font-medium text-white">{diffResults.added.length.toLocaleString()}</p>
                        <p className="text-xs text-gray-500 mt-1">New files identified in target.</p>
                    </div>
                    <div className="bg-[#141414] border border-[#222] rounded-xl p-6 border-l-4 border-l-red-500">
                        <div className="flex justify-between items-center mb-2">
                            <h3 className="text-xs font-bold text-red-400 uppercase tracking-widest">Removed</h3>
                            <ShieldAlert className="w-4 h-4 text-red-500" />
                        </div>
                        <p className="text-2xl font-medium text-white">{diffResults.removed.length.toLocaleString()}</p>
                        <p className="text-xs text-gray-500 mt-1">Files missing from baseline.</p>
                    </div>
                    <div className="bg-[#141414] border border-[#222] rounded-xl p-6 border-l-4 border-l-orange-500">
                        <div className="flex justify-between items-center mb-2">
                            <h3 className="text-xs font-bold text-orange-400 uppercase tracking-widest">Modified</h3>
                            <Activity className="w-4 h-4 text-orange-500" />
                        </div>
                        <p className="text-2xl font-medium text-white">{diffResults.modified.length.toLocaleString()}</p>
                        <p className="text-xs text-gray-500 mt-1">Files with content discrepancies.</p>
                    </div>
                </div>

                <div className="bg-[#0F0F0F] border border-[#222] rounded-xl overflow-hidden flex flex-col min-h-[600px]">
                    <div className="bg-[#141414] border-b border-[#222] p-4 flex gap-4">
                        <h2 className="text-sm font-medium text-white flex items-center gap-2">
                            <GripVertical className="w-4 h-4 text-gray-600" />
                            Multi-Diff Result Set
                        </h2>
                    </div>
                    <div className="flex-1 overflow-auto p-4 space-y-4">
                        {/* Modified Section */}
                        {diffResults.modified.length > 0 && (
                            <div className="space-y-3">
                                <h3 className="text-xs font-bold text-orange-400 uppercase tracking-widest bg-orange-400/5 px-3 py-1 rounded inline-block">Content Divergence</h3>
                                <div className="grid gap-2">
                                    {diffResults.modified.slice(0, 100).map((diff: any, i: number) => (
                                        <div key={i} className="bg-[#161616] border border-orange-500/20 p-3 rounded-lg flex flex-col gap-2 group hover:bg-[#1A1A1A] transition">
                                            <div className="flex justify-between items-start">
                                                <span className="text-sm text-white font-mono truncate">{diff.path}</span>
                                                <span className="text-[10px] bg-orange-500/10 text-orange-400 px-2 py-0.5 rounded border border-orange-500/20">MODIFIED</span>
                                            </div>
                                            <div className="grid grid-cols-2 gap-4">
                                                <div className="flex flex-col gap-1">
                                                    <span className="text-[10px] text-gray-600 uppercase">Baseline Hash</span>
                                                    <span className="text-[10px] font-mono text-gray-400 truncate">{diff.a.sha256}</span>
                                                </div>
                                                <div className="flex flex-col gap-1">
                                                    <span className="text-[10px] text-gray-600 uppercase">Target Hash</span>
                                                    <span className="text-[10px] font-mono text-orange-400 truncate">{diff.b.sha256}</span>
                                                </div>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}

                        {/* Added Section */}
                        {diffResults.added.length > 0 && (
                            <div className="space-y-3">
                                <h3 className="text-xs font-bold text-emerald-400 uppercase tracking-widest bg-emerald-400/5 px-3 py-1 rounded inline-block">New Artifacts</h3>
                                <div className="grid gap-2">
                                    {diffResults.added.slice(0, 100).map((file: any, i: number) => (
                                        <div key={i} className="bg-[#161616] border border-emerald-500/20 p-3 rounded-lg flex justify-between items-center group hover:bg-[#1A1A1A] transition">
                                            <div className="flex flex-col gap-1 truncate">
                                                <span className="text-sm text-white font-mono truncate">{file.path}</span>
                                                <div className="flex gap-3 items-center">
                                                    <span className="text-[10px] text-gray-600">{formatBytes(file.size)}</span>
                                                    <span className="text-[10px] text-gray-600 font-mono">{file.sha256?.slice(0, 16)}...</span>
                                                </div>
                                            </div>
                                            <span className="text-[10px] bg-emerald-500/10 text-emerald-400 px-2 py-0.5 rounded border border-emerald-500/20">ADDED</span>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}

                        {/* Removed Section */}
                        {diffResults.removed.length > 0 && (
                            <div className="space-y-3">
                                <h3 className="text-xs font-bold text-red-400 uppercase tracking-widest bg-red-400/5 px-3 py-1 rounded inline-block">Deleted Entities</h3>
                                <div className="grid gap-2">
                                    {diffResults.removed.slice(0, 100).map((file: any, i: number) => (
                                        <div key={i} className="bg-[#161616] border border-red-500/20 p-3 rounded-lg flex justify-between items-center group hover:bg-[#1A1A1A] transition">
                                            <div className="flex flex-col gap-1 truncate opacity-50">
                                                <span className="text-sm text-white font-mono truncate">{file.path}</span>
                                                <span className="text-[10px] text-gray-600">{formatBytes(file.size)}</span>
                                            </div>
                                            <span className="text-[10px] bg-red-500/10 text-red-400 px-2 py-0.5 rounded border border-red-500/20">REMOVED</span>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}
                    </div>
                </div>
            </motion.div>
        )}
      </main>
    </div>
  );
}
