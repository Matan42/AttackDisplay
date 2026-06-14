import { useState } from 'react';
import BotTab from './BotTab';
import MitreTab from './MitreTab';
import SandboxTab from './SandboxTab';
import './App.css';

export default function App() {
  const [activeTab, setActiveTab] = useState('mitre');

  return (
    <div className="app-shell">
      <header className="app-header">
        <div>
          <div className="app-title">MAGSHIMIM 2026 - Cyber Intelligence Hub</div>
          <div className="app-subtitle">Choose between the attack library, cyber command bot, or sandbox analysis center.</div>
        </div>

        <div className="tab-buttons">
          <button
            className={`tab-button ${activeTab === 'mitre' ? 'active' : ''}`}
            onClick={() => setActiveTab('mitre')}
          >
            Attack Library
          </button>
          <button
            className={`${activeTab === 'bot' ? 'active' : ''} tab-button`}
            onClick={() => setActiveTab('bot')}
          >
            Cyber Bot
          </button>
          <button
            className={`${activeTab === 'sandbox' ? 'active' : ''} tab-button`}
            onClick={() => setActiveTab('sandbox')}
          >
            Sandbox Analysis
          </button>
        </div>
      </header>

      <main className="app-tab-content">
        {activeTab === 'mitre' ? (
          <MitreTab />
        ) : activeTab === 'bot' ? (
          <BotTab />
        ) : (
          <SandboxTab />
        )}
      </main>
    </div>
  );
}