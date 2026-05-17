'use client';

import { useState } from 'react';
import { Copy, Check } from 'lucide-react';
import { Technique } from '@/lib/pwn-data';

interface PwnInspectorProps {
  selectedNode: Technique | null;
}

type TabType = 'overview' | 'prerequisites' | 'constraints' | 'blueprint';

export function PwnInspector({ selectedNode }: PwnInspectorProps) {
  const [activeTab, setActiveTab] = useState<TabType>('overview');
  const [copiedTab, setCopiedTab] = useState<TabType | null>(null);

  if (!selectedNode || selectedNode.id === 'root') {
    return (
      <div className="pwn-inspector">
        <div className="pwn-inspector-header">
          <div className="pwn-inspector-title">Explorer</div>
        </div>
        <div className="pwn-inspector-content flex items-center justify-center text-gray-500">
          <p className="text-center">Select a technique to view details</p>
        </div>
      </div>
    );
  }

  const handleCopy = (text: string, tab: TabType) => {
    navigator.clipboard.writeText(text);
    setCopiedTab(tab);
    setTimeout(() => setCopiedTab(null), 2000);
  };

  const getCategoryBadge = () => {
    const badges: Record<string, { label: string; color: string }> = {
      recon: { label: 'Reconnaissance', color: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/50' },
      technique: { label: 'Technique', color: 'bg-cyan-500/20 text-cyan-300 border-cyan-500/50' },
      mitigation: { label: 'Mitigation', color: 'bg-amber-500/20 text-amber-300 border-amber-500/50' },
      leaf: { label: 'Exploitation', color: 'bg-rose-500/20 text-rose-300 border-rose-500/50' },
    };
    const badge = badges[selectedNode.category];
    if (!badge) return null;

    return (
      <span className={`text-xs font-mono px-2 py-1 rounded border ${badge.color}`}>{badge.label}</span>
    );
  };

  const renderTabContent = () => {
    switch (activeTab) {
      case 'overview':
        return (
          <div className="pwn-section">
            <p className="pwn-section-content">{selectedNode.description}</p>
          </div>
        );

      case 'prerequisites':
        return (
          <div className="pwn-section">
            {selectedNode.prerequisites.length > 0 ? (
              <ul className="pwn-section-content">
                {selectedNode.prerequisites.map((req, idx) => (
                  <li key={idx} className="flex gap-2">
                    <span className="text-cyan-500 flex-shrink-0">›</span>
                    <span>{req}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-gray-500">No specific prerequisites</p>
            )}
          </div>
        );

      case 'constraints':
        return (
          <div className="pwn-section">
            {selectedNode.constraints.length > 0 ? (
              <ul className="pwn-section-content">
                {selectedNode.constraints.map((constraint, idx) => (
                  <li key={idx} className="flex gap-2">
                    <span className="text-rose-500 flex-shrink-0">•</span>
                    <span>{constraint}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-gray-500">No constraints listed</p>
            )}
          </div>
        );

      case 'blueprint':
        return (
          <div className="pwn-section">
            <div className="relative">
              <pre className="pwn-code-block">
                <code className="pwn-code-line">{selectedNode.blueprint}</code>
              </pre>
              <button
                onClick={() => handleCopy(selectedNode.blueprint, 'blueprint')}
                className="absolute top-2 right-2 p-1 bg-cyan-500/20 hover:bg-cyan-500/40 rounded border border-cyan-500/50 text-cyan-400 transition-colors"
              >
                {copiedTab === 'blueprint' ? (
                  <Check className="w-4 h-4" />
                ) : (
                  <Copy className="w-4 h-4" />
                )}
              </button>
            </div>
          </div>
        );

      default:
        return null;
    }
  };

  return (
    <div className="pwn-inspector">
      <div className="pwn-inspector-header">
        <div className="pwn-inspector-title">{selectedNode.name}</div>
        <div className="mt-2">{getCategoryBadge()}</div>
      </div>

      <div className="pwn-inspector-tabs">
        {(['overview', 'prerequisites', 'constraints', 'blueprint'] as TabType[]).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`pwn-inspector-tab ${activeTab === tab ? 'active' : ''}`}
          >
            {tab.charAt(0).toUpperCase() + tab.slice(1)}
          </button>
        ))}
      </div>

      <div className="pwn-inspector-content">{renderTabContent()}</div>
    </div>
  );
}
