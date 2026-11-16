import React from 'react';
import ReactDOM from 'react-dom/client';

export const OptionsApp: React.FC = () => {
  return (
    <div className="max-w-xl mx-auto p-6 font-sans">
      <h1 className="text-2xl font-bold text-slate-800">PhishGuard Settings</h1>
      <p className="text-sm text-slate-600 mt-2">Manage detection sensitivity and trusted domains.</p>
    </div>
  );
};

const root = document.getElementById('root');
if (root) {
  ReactDOM.createRoot(root).render(<OptionsApp />);
}

