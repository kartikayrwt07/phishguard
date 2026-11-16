import React from 'react';
import ReactDOM from 'react-dom/client';

export const WarningApp: React.FC = () => {
  return (
    <div className="min-h-screen flex items-center justify-center bg-red-950 text-white font-sans p-6">
      <div className="max-w-lg bg-red-900/60 p-8 rounded-xl border border-red-500 shadow-2xl">
        <h1 className="text-3xl font-extrabold text-red-300">Warning: Deceptive Site Ahead</h1>
        <p className="mt-4 text-slate-200">
          PhishGuard has detected strong indicators of phishing on this destination.
        </p>
      </div>
    </div>
  );
};

const root = document.getElementById('root');
if (root) {
  ReactDOM.createRoot(root).render(<WarningApp />);
}

