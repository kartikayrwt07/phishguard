import React, { useEffect, useState } from 'react';
import ReactDOM from 'react-dom/client';
import { sendMessageToBackground } from '../shared/messages';
import { ScanResult } from '../shared/types';
import { HeuristicEngine } from '../detection/heuristics';

export interface WarningAppProps {
  initialBlockedUrl?: string;
  initialScanResult?: ScanResult;
  onNavigate?: (destination: string) => void;
  onBack?: () => void;
}

function extractDomain(rawUrl: string): string {
  try {
    return new URL(rawUrl).hostname;
  } catch {
    return rawUrl;
  }
}

export const WarningApp: React.FC<WarningAppProps> = ({
  initialBlockedUrl,
  initialScanResult,
  onNavigate,
  onBack,
}) => {
  const getInitialUrl = (): string => {
    if (initialBlockedUrl) return initialBlockedUrl;
    if (typeof window !== 'undefined' && window.location && window.location.search) {
      const params = new URLSearchParams(window.location.search);
      return params.get('blocked_url') || '';
    }
    return '';
  };

  const [blockedUrl, setBlockedUrl] = useState<string>(getInitialUrl);
  const [domain, setDomain] = useState<string>(() => {
    const u = getInitialUrl();
    return u ? extractDomain(u) : '';
  });

  const [scanResult, setScanResult] = useState<ScanResult | null>(() => {
    if (initialScanResult) return initialScanResult;
    const u = getInitialUrl();
    if (u) {
      try {
        return HeuristicEngine.analyze(u);
      } catch {
        return null;
      }
    }
    return null;
  });

  const [loading, setLoading] = useState<boolean>(false);
  const [showAdvanced, setShowAdvanced] = useState<boolean>(false);
  const [bypassing, setBypassing] = useState<boolean>(false);
  const [feedbackMessage, setFeedbackMessage] = useState<string | null>(null);

  // Background enrichment / update check
  useEffect(() => {
    const url = blockedUrl || getInitialUrl();
    if (!url) return;

    if (!blockedUrl) {
      setBlockedUrl(url);
      setDomain(extractDomain(url));
    }

    if (initialScanResult) {
      setScanResult(initialScanResult);
      return;
    }

    async function fetchScanData(targetUrl: string) {
      setLoading(true);
      try {
        // 1. Try cache
        const cacheResp = await sendMessageToBackground<ScanResult>({
          type: 'GET_SCAN_CACHE',
          payload: { url: targetUrl },
        });

        if (cacheResp.success && cacheResp.data) {
          setScanResult(cacheResp.data);
          return;
        }

        // 2. Try fresh analysis via background service worker
        const analyzeResp = await sendMessageToBackground<ScanResult>({
          type: 'ANALYZE_URL',
          payload: { url: targetUrl },
        });

        if (analyzeResp.success && analyzeResp.data) {
          setScanResult(analyzeResp.data);
          return;
        }
      } catch {
        // Fallback already pre-initialized
      } finally {
        setLoading(false);
      }
    }

    fetchScanData(url);
  }, [blockedUrl, initialBlockedUrl, initialScanResult]);

  const handleBackToSafety = () => {
    if (onBack) {
      onBack();
      return;
    }
    if (typeof window !== 'undefined') {
      if (window.history.length > 1) {
        window.history.back();
      } else {
        window.location.href = 'https://www.google.com';
      }
    }
  };

  const handleBypassOnce = async () => {
    setBypassing(true);
    setFeedbackMessage('Bypassing protection for this navigation...');

    try {
      await sendMessageToBackground({
        type: 'BYPASS_BLOCK',
        payload: { domain, url: blockedUrl },
      });
    } catch {
      // Continue navigation even if message fails
    }

    if (onNavigate) {
      onNavigate(blockedUrl);
    } else if (typeof window !== 'undefined') {
      window.location.href = blockedUrl;
    }
    setBypassing(false);
  };

  const handleAlwaysTrust = async () => {
    setBypassing(true);
    setFeedbackMessage(`Adding ${domain} to trusted allowlist...`);

    try {
      await sendMessageToBackground({
        type: 'ADD_ALLOWLIST',
        payload: {
          domain,
          reason: 'Trusted by user via warning interstitial override',
        },
      });
    } catch {
      // Continue navigation even if message fails
    }

    if (onNavigate) {
      onNavigate(blockedUrl);
    } else if (typeof window !== 'undefined') {
      window.location.href = blockedUrl;
    }
    setBypassing(false);
  };

  const isPhishing = scanResult?.verdict === 'PHISHING';
  const score = scanResult ? Math.round(scanResult.score) : 85;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans flex flex-col justify-between p-4 sm:p-8">
      {/* Top Brand Bar */}
      <header className="max-w-4xl w-full mx-auto flex items-center justify-between pb-6 border-b border-slate-800">
        <div className="flex items-center space-x-3">
          <div className="w-8 h-8 rounded-lg bg-red-600 flex items-center justify-center font-black text-white text-base shadow-md">
            🛡️
          </div>
          <div>
            <span className="font-bold text-lg tracking-tight text-white">PhishGuard</span>
            <span className="text-xs ml-2 px-2 py-0.5 rounded bg-red-950 text-red-400 border border-red-800 font-mono">
              INTERCEPTOR ACTIVE
            </span>
          </div>
        </div>
        <span className="text-xs text-slate-400 font-mono">Manifest V3 Protected</span>
      </header>

      {/* Main Warning Content Container */}
      <main className="max-w-3xl w-full mx-auto my-8 space-y-6">
        {/* Urgent Alert Banner */}
        <div className="bg-red-950/80 border-2 border-red-600/70 rounded-2xl p-6 sm:p-8 shadow-2xl backdrop-blur">
          <div className="flex items-start space-x-4">
            <div className="p-3 bg-red-900/60 rounded-xl text-3xl border border-red-500/50 flex-shrink-0 animate-pulse">
              ⚠️
            </div>
            <div className="flex-1">
              <div className="flex items-center space-x-3">
                <span className="px-2.5 py-0.5 rounded text-xs font-bold tracking-wide uppercase bg-red-600 text-white shadow">
                  {isPhishing ? 'High Risk Threat' : 'Suspicious Site Detected'}
                </span>
                <span className="text-sm font-semibold text-red-300">
                  {`Risk Score: ${score}/100`}
                </span>
              </div>
              <h1 className="text-2xl sm:text-3xl font-black text-white mt-2 tracking-tight">
                Deceptive Destination Blocked
              </h1>
              <p className="mt-2 text-slate-200 text-sm sm:text-base leading-relaxed">
                PhishGuard blocked navigation to this website because it exhibits deceptive indicators of
                credential theft, brand spoofing, or fraudulent activity.
              </p>

              {/* Blocked URL Box */}
              <div className="mt-4 p-3 bg-slate-900/90 rounded-lg border border-slate-700 font-mono text-xs text-slate-300 break-all flex flex-col space-y-1">
                <div className="flex items-center justify-between text-slate-400 border-b border-slate-800 pb-1">
                  <span>Target Destination:</span>
                  <span className="text-red-400 font-bold">{domain || 'Unknown Domain'}</span>
                </div>
                <div className="text-slate-300 select-all pt-1">
                  {blockedUrl || 'No target URL specified.'}
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Explainable Evidence Section */}
        {loading ? (
          <div className="bg-slate-900 p-6 rounded-xl border border-slate-800 text-center text-slate-400">
            Analyzing security indicators...
          </div>
        ) : (
          scanResult && (
            <div className="bg-slate-900/90 rounded-xl border border-slate-800 p-6 space-y-4">
              <div className="flex items-center justify-between">
                <h2 className="text-base font-bold text-white flex items-center space-x-2">
                  <span>Detection Evidence & Threat Breakdown</span>
                  <span className="text-xs font-normal text-slate-400">
                    {`(${scanResult.evidence.length} indicators found)`}
                  </span>
                </h2>
                <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
                  {`Confidence: ${Math.round(scanResult.confidence * 100)}%`}
                </span>
              </div>

              {scanResult.evidence.length === 0 ? (
                <p className="text-sm text-slate-400">No specific heuristic flags were recorded.</p>
              ) : (
                <div className="space-y-2">
                  {scanResult.evidence.map((item, idx) => (
                    <div
                      key={item.id || idx}
                      className="p-3 bg-slate-950/70 border border-slate-800/80 rounded-lg flex items-start justify-between space-x-3 text-xs"
                    >
                      <div className="space-y-1 flex-1">
                        <div className="flex items-center space-x-2">
                          <span className="font-bold text-red-400 font-mono">
                            {item.rule_name}
                          </span>
                          <span className="text-slate-400 text-[10px] px-1.5 py-0.5 rounded bg-slate-800">
                            {item.layer}
                          </span>
                        </div>
                        <p className="text-slate-300 leading-normal">{item.description}</p>
                      </div>
                      <div className="text-right flex-shrink-0">
                        <span className="px-2 py-0.5 rounded text-red-300 bg-red-950/80 border border-red-800/60 font-bold font-mono">
                          {`+${item.score_impact} pts`}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )
        )}

        {/* Primary Safe Action Controls */}
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-4 pt-2">
          <button
            data-testid="leave-site-btn"
            onClick={handleBackToSafety}
            className="flex-1 py-3.5 px-6 rounded-xl bg-emerald-600 hover:bg-emerald-500 active:bg-emerald-700 text-white font-bold text-base shadow-lg transition-all flex items-center justify-center space-x-2"
          >
            <span>← Back to Safety (Recommended)</span>
          </button>

          <button
            data-testid="toggle-advanced-btn"
            onClick={() => setShowAdvanced(!showAdvanced)}
            className="py-3.5 px-5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-sm font-medium border border-slate-700 transition-colors"
          >
            {showAdvanced ? 'Hide Advanced Options' : 'Advanced Options'}
          </button>
        </div>

        {/* Advanced Unsafe Proceed & Allowlist Section */}
        {showAdvanced && (
          <div
            data-testid="advanced-panel"
            className="mt-6 p-6 rounded-xl bg-slate-900/90 border border-amber-900/60 space-y-4 text-xs sm:text-sm text-slate-300 animate-fadeIn"
          >
            <div className="flex items-start space-x-3">
              <span className="text-amber-400 text-xl flex-shrink-0">⚠️</span>
              <div>
                <h3 className="font-bold text-amber-300 text-sm">Proceeding is strongly discouraged</h3>
                <p className="mt-1 text-slate-300 leading-relaxed text-xs">
                  Attackers often spoof reputable institutions to harvest credentials, session tokens, or personal identity numbers.
                  If you bypass this protection, any data you provide on this destination may be compromised.
                </p>
              </div>
            </div>

            {feedbackMessage && (
              <div className="p-2.5 rounded bg-slate-800 text-amber-300 text-xs font-mono">
                {feedbackMessage}
              </div>
            )}

            <div className="pt-2 flex flex-col sm:flex-row gap-3 border-t border-slate-800">
              <button
                data-testid="bypass-once-btn"
                disabled={bypassing || !blockedUrl}
                onClick={handleBypassOnce}
                className="py-2.5 px-4 rounded-lg bg-red-950/80 hover:bg-red-900 text-red-200 border border-red-700/60 font-semibold text-xs transition-colors disabled:opacity-50"
              >
                Proceed Anyway (Unsafe, One-Time Bypass)
              </button>

              <button
                data-testid="always-trust-btn"
                disabled={bypassing || !domain}
                onClick={handleAlwaysTrust}
                className="py-2.5 px-4 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-600 font-semibold text-xs transition-colors disabled:opacity-50"
              >
                Always Trust {domain || 'Domain'} (Add to Allowlist)
              </button>
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="max-w-4xl w-full mx-auto pt-6 border-t border-slate-800/80 text-center text-xs text-slate-500">
        PhishGuard v1.0 • Privacy Preserving Browser Protection • Zero Secrets Collected
      </footer>
    </div>
  );
};

if (typeof document !== 'undefined') {
  const root = document.getElementById('root');
  if (root) {
    ReactDOM.createRoot(root).render(<WarningApp />);
  }
}
