import React from 'react';
import ReactDOM from 'react-dom/client';

export const PopupApp: React.FC = () => {
  return (
    <div className="w-80 p-4 font-sans bg-slate-900 text-slate-100">
      <div className="flex items-center justify-between pb-3 border-b border-slate-700">
        <h1 className="text-lg font-bold text-emerald-400">PhishGuard</h1>
        <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-400">v1.0.0</span>
      </div>
      <div className="py-4 text-center">
        <p className="text-sm text-slate-300">Active real-time protection enabled.</p>
      </div>
    </div>
  );
};

const root = document.getElementById('root');
if (root) {
  ReactDOM.createRoot(root).render(<PopupApp />);
}

