import React, { useEffect, useState } from 'react';
import ReactDOM from 'react-dom/client';
import { sendMessageToBackground } from '../shared/messages';
import { AllowlistEntry, ScanResult, ScanVerdict } from '../shared/types';

export const PopupApp: React.FC = () => {
  const [currentUrl, setCurrentUrl] = useState<string>('');
  const [currentDomain, setCurrentDomain] = useState<string>('');
  const [tabId, setTabId] = useState<number | undefined>(undefined);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [isAllowlisted, setIsAllowlisted] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Load current active tab on mount
  useEffect(() => {
    async function loadActiveTab() {
      setLoading(true);
      setError(null);

      if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.query) {
        chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
          const activeTab = tabs[0];
          if (!activeTab || !activeTab.url) {
            setError('No active web page detected.');
            setLoading(false);
            return;
          }

          const url = activeTab.url;
          setCurrentUrl(url);
          setTabId(activeTab.id);

          try {
            const urlObj = new URL(url);
            setCurrentDomain(urlObj.hostname);

            // Check if domain is allowlisted
            const allowResp = await sendMessageToBackground<AllowlistEntry[]>({
              type: 'GET_ALLOWLIST',
            });
            if (allowResp.success && allowResp.data) {
              const allowed = allowResp.data.some(
                (e) => e.domain === urlObj.hostname || urlObj.hostname.endsWith(`.${e.domain}`)
              );
              setIsAllowlisted(allowed);
            }

            // Request URL analysis
            const scanResp = await sendMessageToBackground<ScanResult>({
              type: 'ANALYZE_URL',
              payload: {
                url,
                tabId: activeTab.id,
              },
            });

            if (scanResp.success && scanResp.data) {
              setScanResult(scanResp.data);
            } else {
              setError(scanResp.error || 'Failed to analyze URL');
            }
          } catch (err) {
            setError('Non-standard or internal browser URL.');
          } finally {
            setLoading(false);
          }
        });
      } else {
        // Fallback mock for browser preview / development
        setCurrentUrl('https://example.com/login');
        setCurrentDomain('example.com');
        setScanResult({
          url: 'https://example.com/login',
          domain: 'example.com',
          verdict: 'SAFE',
          score: 10,
          confidence: 0.95,
          evidence: [],
          source: 'local',
          scanned_at: new Date().toISOString(),
          engine_version: '1.0.0',
        });
        setLoading(false);
      }
    }

    loadActiveTab();
  }, []);

  const handleToggleAllowlist = async () => {
    if (!currentDomain) return;
    setLoading(true);

    if (isAllowlisted) {
      await sendMessageToBackground({
        type: 'REMOVE_ALLOWLIST',
        payload: { domain: currentDomain },
      });
      setIsAllowlisted(false);
    } else {
      await sendMessageToBackground({
        type: 'ADD_ALLOWLIST',
        payload: { domain: currentDomain, reason: 'Manually trusted by user' },
      });
      setIsAllowlisted(true);
    }

    // Refresh scan
    const resp = await sendMessageToBackground<ScanResult>({
      type: 'ANALYZE_URL',
      payload: { url: currentUrl, tabId, forceEnrichment: true },
    });
    if (resp.success && resp.data) {
      setScanResult(resp.data);
    }
    setLoading(false);
  };

  const handleRescan = async () => {
    if (!currentUrl) return;
    setLoading(true);
    const resp = await sendMessageToBackground<ScanResult>({
      type: 'ANALYZE_URL',
      payload: { url: currentUrl, tabId, forceEnrichment: true },
    });
    if (resp.success && resp.data) {
      setScanResult(resp.data);
    }
    setLoading(false);
  };

  const handleOpenOptions = () => {
    if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.openOptionsPage) {
      chrome.runtime.openOptionsPage();
    }
  };

  const getVerdictBadge = (verdict?: ScanVerdict) => {
    switch (verdict) {
      case 'SAFE':
        return <span className="px-2.5 py-1 rounded-full text-xs font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">SAFE</span>;
      case 'SUSPICIOUS':
        return <span className="px-2.5 py-1 rounded-full text-xs font-bold bg-amber-500/20 text-amber-400 border border-amber-500/30">SUSPICIOUS</span>;
      case 'PHISHING':
        return <span className="px-2.5 py-1 rounded-full text-xs font-bold bg-red-500/20 text-red-400 border border-red-500/30">PHISHING</span>;
      default:
        return <span className="px-2.5 py-1 rounded-full text-xs font-bold bg-slate-700 text-slate-300">UNKNOWN</span>;
    }
  };

  const getScoreColor = (score: number) => {
    if (score >= 70) return '#ef4444'; // red
    if (score >= 30) return '#eab308'; // yellow
    return '#22c55e'; // green
  };

  return (
    <div className="w-[340px] bg-slate-900 text-slate-100 font-sans p-4 shadow-xl select-none">
      {/* Header */}
      <div className="flex items-center justify-between pb-3 border-b border-slate-800">
        <div className="flex items-center gap-2">
          <div className="w-6 h-6 rounded-md bg-emerald-500/20 flex items-center justify-center border border-emerald-500/30">
            <svg className="w-3.5 h-3.5 text-emerald-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
          </div>
          <span className="font-bold text-sm tracking-wide text-slate-100">PhishGuard</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">v1.0.0</span>
          <button
            onClick={handleOpenOptions}
            className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition"
            title="Open Settings"
          >
            <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="3"/>
              <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/>
            </svg>
          </button>
        </div>
      </div>

      {/* Target Domain */}
      <div className="mt-3 p-2.5 rounded-lg bg-slate-800/60 border border-slate-700/60 flex items-center justify-between">
        <div className="overflow-hidden pr-2">
          <p className="text-[11px] text-slate-400 uppercase tracking-wider font-semibold">Inspected Domain</p>
          <p className="text-xs font-mono font-medium text-slate-200 truncate" title={currentDomain || currentUrl}>
            {currentDomain || 'Unknown'}
          </p>
        </div>
        <div>{getVerdictBadge(scanResult?.verdict)}</div>
      </div>

      {/* Risk Score & Gauge */}
      {scanResult && !error && (
        <div className="mt-3 p-3 rounded-lg bg-slate-800/40 border border-slate-800 text-center">
          <div className="flex items-center justify-center gap-4">
            <div className="relative w-16 h-16 flex items-center justify-center">
              <svg className="w-full h-full transform -rotate-90" viewBox="0 0 36 36">
                <path
                  className="text-slate-700"
                  strokeWidth="3.5"
                  stroke="currentColor"
                  fill="none"
                  d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                />
                <path
                  strokeWidth="3.5"
                  strokeDasharray={`${scanResult.score}, 100`}
                  strokeLinecap="round"
                  stroke={getScoreColor(scanResult.score)}
                  fill="none"
                  d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                />
              </svg>
              <span className="absolute text-sm font-bold font-mono">
                {Math.round(scanResult.score)}
              </span>
            </div>

            <div className="text-left">
              <p className="text-xs font-semibold text-slate-300">
                Risk Score: {scanResult.score}/100
              </p>
              <p className="text-[11px] text-slate-400 mt-0.5">
                Confidence: {Math.round(scanResult.confidence * 100)}%
              </p>
              <span className="inline-block mt-1 text-[10px] px-1.5 py-0.5 rounded bg-slate-700/80 text-slate-300">
                Source: {scanResult.source === 'cloud' ? 'Cloud Threat Feeds' : scanResult.source === 'override' ? 'User Allowlist' : 'Local Heuristics'}
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Itemized Evidence */}
      {scanResult && (
        <div className="mt-3">
          <p className="text-[11px] uppercase tracking-wider text-slate-400 font-semibold mb-1.5">
            Detection Evidence ({scanResult.evidence.length})
          </p>

          <div className="max-h-36 overflow-y-auto space-y-1.5 pr-1">
            {scanResult.evidence.length > 0 ? (
              scanResult.evidence.map((item, idx) => (
                <div key={idx} className="p-2 rounded bg-slate-800/80 border border-slate-700/50 text-[11px]">
                  <div className="flex items-center justify-between font-semibold text-slate-300">
                    <span className="font-mono text-amber-300 text-[10px]">{item.rule_name}</span>
                    <span className="text-red-400">+{item.score_impact} pts</span>
                  </div>
                  <p className="text-slate-400 mt-1 leading-relaxed">{item.description}</p>
                </div>
              ))
            ) : (
              <div className="p-2.5 rounded bg-emerald-950/30 border border-emerald-900/50 text-[11px] text-emerald-300 flex items-center gap-2">
                <svg className="w-4 h-4 text-emerald-400 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <polyline points="20 6 9 17 4 12"/>
                </svg>
                <span>No deceptive or harvesting indicators detected.</span>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Error state */}
      {error && (
        <div className="mt-3 p-3 rounded bg-slate-800 border border-slate-700 text-center">
          <p className="text-xs text-slate-300">{error}</p>
        </div>
      )}

      {/* Footer Controls */}
      <div className="mt-4 pt-3 border-t border-slate-800 flex items-center gap-2">
        <button
          onClick={handleToggleAllowlist}
          disabled={loading || !currentDomain}
          className={`flex-1 py-1.5 px-3 rounded text-xs font-semibold border transition ${
            isAllowlisted
              ? 'bg-amber-600/20 text-amber-300 border-amber-600/40 hover:bg-amber-600/30'
              : 'bg-slate-800 text-slate-200 border-slate-700 hover:bg-slate-750'
          }`}
        >
          {isAllowlisted ? 'Untrust Domain' : 'Trust Domain'}
        </button>

        <button
          onClick={handleRescan}
          disabled={loading}
          className="py-1.5 px-3 rounded bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold transition disabled:opacity-50"
        >
          {loading ? 'Scanning...' : 'Re-scan'}
        </button>
      </div>
    </div>
  );
};

const rootEl = document.getElementById('root');
if (rootEl) {
  ReactDOM.createRoot(rootEl).render(<PopupApp />);
}
