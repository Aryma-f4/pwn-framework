'use client';

import { useState, useEffect } from 'react';
import { Copy, Check, ExternalLink, Github, BookOpen } from 'lucide-react';
import { Technique } from '@/lib/pwn-data';
import { getTechniqueKB, enrichedTechnique } from '@/lib/pwn-unified-data';
import { getHeapReferenceForTechnique } from '@/lib/heap-reference-mapping';
import { InteractiveChecklist } from './interactive-checklist';
import { SessionManager } from './session-manager';
import { useSessions, ChecklistItem } from '@/lib/use-sessions';
import { ReconWizard } from './recon-wizard';
import { ExploitRecommender } from './exploit-recommender';

interface PwnInspectorProps {
  selectedNode: Technique | null;
  reconTags?: Set<string>;
  onReconTagsChange?: (tags: Set<string>) => void;
  onSelectTechniqueById?: (techniqueId: string) => void;
}

type TabType = 'overview' | 'prerequisites' | 'constraints' | 'blueprint' | 'precond' | 'exploits' | 'checklist' | 'refs' | 'heap' | 'resources' | 'sessions' | 'recon';

export function PwnInspector({ selectedNode, reconTags = new Set(), onReconTagsChange, onSelectTechniqueById }: PwnInspectorProps) {
  const [activeTab, setActiveTab] = useState<TabType>('overview');
  const [copiedTab, setCopiedTab] = useState<string | null>(null);
  const { sessions, activeSessionId, setActiveSessionId, createSession, deleteSession, renameSession, updateChecklistItem, setChecklist, getActiveSession, isLoaded } = useSessions();
  
  // Initialize session when technique changes
  useEffect(() => {
    if (selectedNode && selectedNode.id !== 'root' && isLoaded) {
      const activeSession = getActiveSession();
      // If no session or different technique, create one
      if (!activeSession || activeSession.technique !== selectedNode.id) {
        const defaultChecklist: ChecklistItem[] = [];
        if (getTechniqueKB(selectedNode.id)?.operatorChecklist) {
          const kb = getTechniqueKB(selectedNode.id);
          defaultChecklist.push(...kb.operatorChecklist.map((text: string, idx: number) => ({
            id: `item_${idx}`,
            text: text.substring(5).trim(),
            completed: false,
          })));
        }
        createSession(selectedNode.name, defaultChecklist);
      }
    }
  }, [selectedNode?.id, isLoaded]);

  if (!selectedNode || selectedNode.id === 'root') {
    return (
      <div className="pwn-inspector">
        <div className="pwn-inspector-header">
          <div className="pwn-inspector-title">🎯 Pre-Pwn Recon</div>
        </div>
        <div className="pwn-inspector-content">
          <ReconWizard selectedTags={reconTags} onTagsChange={onReconTagsChange || (() => {})} />
          <div className="pt-2 border-t border-slate-800">
            <ExploitRecommender selectedTags={reconTags} onSelectTechnique={onSelectTechniqueById || (() => {})} />
          </div>
        </div>
      </div>
    );
  }

  // Get knowledge base entry for this technique
  const kbEntry = getTechniqueKB(selectedNode.id);
  const hasKB = !!kbEntry;

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedTab(id);
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
    if (hasKB && kbEntry) {
      switch (activeTab) {
        case 'overview':
          return (
            <div className="pwn-section space-y-3">
              <p className="pwn-section-content text-gray-300">{kbEntry.description}</p>
              <div>
                <p className="text-xs text-cyan-400 font-mono mb-1">CLASS</p>
                <p className="text-gray-300 text-sm">{kbEntry.class}</p>
              </div>
            </div>
          );

        case 'precond':
          return (
            <div className="pwn-section space-y-3">
              <div>
                <p className="text-xs text-cyan-400 font-mono mb-1">SUMMARY</p>
                <p className="text-gray-300 text-sm">{kbEntry.preconditions.summary}</p>
              </div>
              <div>
                <p className="text-xs text-cyan-400 font-mono mb-1">REQUIRED CONDITIONS</p>
                <ul className="space-y-1">
                  {kbEntry.preconditions.required.map((req, idx) => (
                    <li key={idx} className="text-gray-300 text-xs flex gap-2">
                      <span className="text-cyan-400">▸</span>
                      <span>{req}</span>
                    </li>
                  ))}
                </ul>
              </div>
              <div>
                <p className="text-xs text-emerald-400 font-mono mb-1">DETECTION STEPS</p>
                <ol className="space-y-1">
                  {kbEntry.preconditions.detectionSteps.map((step, idx) => (
                    <li key={idx} className="text-gray-300 text-xs flex gap-2">
                      <span className="text-emerald-400">{idx + 1}.</span>
                      <code className="text-gray-300">{step}</code>
                    </li>
                  ))}
                </ol>
              </div>
            </div>
          );

        case 'exploits':
          return (
            <div className="pwn-section space-y-3">
              {kbEntry.exploitationPaths.map((path, idx) => (
                <div key={idx} className="bg-slate-900/30 border border-slate-700 rounded p-3 space-y-2">
                  <div>
                    <p className="text-cyan-300 font-mono text-sm">{path.name}</p>
                    <p className="text-gray-400 text-xs mt-1">{path.description}</p>
                  </div>
                  <div>
                    <p className="text-xs text-amber-400 font-mono mb-1">Steps:</p>
                    <ol className="space-y-1">
                      {path.steps.map((step, s) => (
                        <li key={s} className="text-gray-300 text-xs">
                          {s + 1}. {step}
                        </li>
                      ))}
                    </ol>
                  </div>
                  <div>
                    <p className="text-xs text-emerald-400 font-mono mb-1">Tools:</p>
                    <div className="flex flex-wrap gap-1">
                      {path.tools.map((tool) => (
                        <span key={tool} className="px-1.5 py-0.5 bg-emerald-900/20 text-emerald-300 text-xs rounded">
                          {tool}
                        </span>
                      ))}
                    </div>
                  </div>
                  {path.codeSnippet && (
                    <div className="relative">
                      <pre className="text-xs bg-black/30 p-2 rounded overflow-x-auto text-gray-300 border border-slate-700">
                        {path.codeSnippet}
                      </pre>
                      <button
                        onClick={() => handleCopy(path.codeSnippet!, `code-${idx}`)}
                        className="absolute top-1 right-1 p-1 bg-slate-700 hover:bg-slate-600 rounded text-xs"
                        title="Copy code"
                      >
                        {copiedTab === `code-${idx}` ? (
                          <Check size={12} className="text-emerald-400" />
                        ) : (
                          <Copy size={12} className="text-gray-400" />
                        )}
                      </button>
                    </div>
                  )}
                </div>
              ))}
            </div>
          );

        case 'checklist': {
          const activeSession = getActiveSession();
          return (
            <div className="pwn-section space-y-4">
              <div>
                <p className="text-xs text-cyan-400 font-mono mb-2">OPERATOR WORKFLOW</p>
                {activeSession && (
                  <InteractiveChecklist
                    items={activeSession.checklist}
                    onItemToggle={(itemId, completed) => updateChecklistItem(activeSession.id, itemId, completed)}
                    onItemAdd={(text) => {
                      const newItem: ChecklistItem = {
                        id: `item_${Date.now()}`,
                        text,
                        completed: false,
                      };
                      setChecklist(activeSession.id, [...activeSession.checklist, newItem]);
                    }}
                    onItemDelete={(itemId) => {
                      setChecklist(activeSession.id, activeSession.checklist.filter(item => item.id !== itemId));
                    }}
                    onItemUpdate={(itemId, text) => {
                      setChecklist(activeSession.id, activeSession.checklist.map(item =>
                        item.id === itemId ? { ...item, text } : item
                      ));
                    }}
                  />
                )}
              </div>
            </div>
          );
        }

        case 'refs':
          return (
            <div className="pwn-section space-y-2">
              {kbEntry.references && kbEntry.references.length > 0 ? (
                kbEntry.references.map((ref, idx) => (
                  <div key={idx} className="bg-slate-900/30 border border-slate-700 rounded p-2 space-y-1">
                    {ref.tool && <p className="text-cyan-300 text-xs font-mono">{ref.tool}</p>}
                    <p className="text-gray-300 text-xs">{ref.description}</p>
                    {ref.url && (
                      <a
                        href={ref.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1"
                      >
                        Read More <ExternalLink size={10} />
                      </a>
                    )}
                  </div>
                ))
              ) : (
                <p className="text-gray-500 text-xs">No references available</p>
              )}
            </div>
          );

        case 'heap':
          const heapRef = getHeapReferenceForTechnique(selectedNode.id);
          return heapRef ? (
            <div className="pwn-section space-y-3">
              <div>
                <p className="text-xs text-purple-400 font-mono mb-1">HEAP TECHNIQUE</p>
                <p className="text-gray-300 font-semibold text-sm">{heapRef.name}</p>
              </div>
              <div>
                <p className="text-xs text-purple-400 font-mono mb-1">CATEGORY</p>
                <p className="text-gray-300 text-sm">{heapRef.category.replace('-', ' ').toUpperCase()}</p>
              </div>
              <div>
                <p className="text-xs text-purple-400 font-mono mb-1">DIFFICULTY</p>
                <span className={`px-2 py-1 rounded text-xs font-mono ${
                  heapRef.difficulty === 'Expert' ? 'bg-red-900/30 text-red-300' :
                  heapRef.difficulty === 'Hard' ? 'bg-orange-900/30 text-orange-300' :
                  heapRef.difficulty === 'Medium' ? 'bg-yellow-900/30 text-yellow-300' :
                  'bg-green-900/30 text-green-300'
                }`}>
                  {heapRef.difficulty}
                </span>
              </div>
              {heapRef.glibcVersions && (
                <div>
                  <p className="text-xs text-purple-400 font-mono mb-1">GLIBC VERSIONS</p>
                  <div className="flex flex-wrap gap-1">
                    {heapRef.glibcVersions.map((v) => (
                      <span key={v} className="px-2 py-0.5 bg-slate-800 text-gray-300 text-xs rounded border border-slate-600">
                        {v}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="pwn-section text-gray-500 text-xs">
              No heap exploitation reference available for this technique.
            </div>
          );

        case 'resources':
          const heapRefRes = getHeapReferenceForTechnique(selectedNode.id);
          return (
            <div className="pwn-section space-y-2">
              {heapRefRes && (
                <>
                  {heapRefRes.how2heapLink && (
                    <a
                      href={heapRefRes.how2heapLink}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="block bg-slate-900/50 border border-slate-700 rounded p-3 hover:border-blue-500/50 transition-all group"
                    >
                      <div className="flex items-center gap-2 mb-1">
                        <Github size={14} className="text-blue-400" />
                        <span className="text-xs font-mono text-blue-300">shellphish/how2heap</span>
                        <ExternalLink size={10} className="opacity-50 group-hover:opacity-100" />
                      </div>
                      <p className="text-xs text-gray-400">Exploiting the Heap</p>
                    </a>
                  )}
                  {heapRefRes.dhavalkapilChapter && (
                    <a
                      href={heapRefRes.dhavalkapilChapter}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="block bg-slate-900/50 border border-slate-700 rounded p-3 hover:border-purple-500/50 transition-all group"
                    >
                      <div className="flex items-center gap-2 mb-1">
                        <BookOpen size={14} className="text-purple-400" />
                        <span className="text-xs font-mono text-purple-300">Heap Exploitation Guide</span>
                        <ExternalLink size={10} className="opacity-50 group-hover:opacity-100" />
                      </div>
                      <p className="text-xs text-gray-400">By Dhavalkapil</p>
                    </a>
                  )}
                </>
              )}
              <div className="bg-slate-800/30 border border-slate-700/50 rounded p-2 text-xs text-gray-400">
                <p className="mb-1 font-mono text-cyan-300">Exploitation Tips:</p>
                <ul className="space-y-0.5 text-xs text-gray-500">
                  <li>• Leak heap addresses via info disclosure</li>
                  <li>• Use gdb breakpoints to inspect heap layout</li>
                  <li>• Test with ASLR disabled first</li>
                  <li>• Verify glibc version matches exploit</li>
                </ul>
              </div>
            </div>
          );

        case 'recon':
          return (
            <div className="pwn-section space-y-3">
              <ReconWizard selectedTags={reconTags} onTagsChange={onReconTagsChange || (() => {})} />
              <div className="pt-2 border-t border-slate-800">
                <ExploitRecommender selectedTags={reconTags} onSelectTechnique={onSelectTechniqueById || (() => {})} />
              </div>
            </div>
          );

        default:
          return null;
      }
    } else {
      // Legacy mode for nodes without KB
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

        case 'recon':
          return (
            <div className="pwn-section space-y-3">
              <ReconWizard selectedTags={reconTags} onTagsChange={onReconTagsChange || (() => {})} />
              <div className="pt-2 border-t border-slate-800">
                <ExploitRecommender selectedTags={reconTags} onSelectTechnique={onSelectTechniqueById || (() => {})} />
              </div>
            </div>
          );

        case 'sessions':
          return (
            <div className="pwn-section">
              <p className="text-xs text-cyan-400 font-mono mb-3">SAVED SESSIONS</p>
              <SessionManager
                sessions={sessions}
                activeSessionId={activeSessionId}
                onCreateSession={(name) => {
                  const newSession = createSession(name, []);
                  setActiveSessionId(newSession);
                }}
                onSelectSession={setActiveSessionId}
                onDeleteSession={deleteSession}
                onRenameSession={renameSession}
                currentTechnique={selectedNode?.name || 'Technique'}
              />
              <p className="text-xs text-gray-500 mt-4 pt-3 border-t border-slate-800">
                Sessions are automatically saved to your browser's local storage. You can create multiple sessions for different techniques and switch between them.
              </p>
            </div>
          );

        default:
          return null;
      }
    }
  };

  const tabs = hasKB
    ? (['overview', 'precond', 'exploits', 'checklist', 'refs', 'heap', 'resources', 'sessions', 'recon'] as TabType[])
    : (['overview', 'prerequisites', 'constraints', 'blueprint', 'heap', 'resources', 'sessions', 'recon'] as TabType[]);

  const tabLabels: Record<TabType, string> = {
    overview: 'Overview',
    prerequisites: 'Prerequisites',
    constraints: 'Constraints',
    blueprint: 'Blueprint',
    precond: 'Preconditions',
    exploits: 'Exploitations',
    checklist: 'Checklist',
    refs: 'References',
    heap: 'Heap Ref',
    resources: 'Resources',
    sessions: 'Sessions',
    recon: '🎯 Recon',
  };

  return (
    <div className="pwn-inspector">
      <div className="pwn-inspector-header">
        <div className="pwn-inspector-title">{selectedNode.name}</div>
        <div className="mt-2">{getCategoryBadge()}</div>
      </div>

      <div className="pwn-inspector-tabs">
        {tabs.map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`pwn-inspector-tab ${activeTab === tab ? 'active' : ''}`}
          >
            {tabLabels[tab]}
          </button>
        ))}
      </div>

      <div className="pwn-inspector-content">{renderTabContent()}</div>
    </div>
  );
}
