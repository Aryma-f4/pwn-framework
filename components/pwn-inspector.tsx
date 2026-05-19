'use client';

import { useState, useEffect } from 'react';
import { Copy, Check, ExternalLink, Github, BookOpen, Search, AlertCircle, FileText, ListChecks, Link2, Database, Layers, Target, FolderOpen } from 'lucide-react';
import { Technique } from '@/lib/pwn-data';
import { getTechniqueKB } from '@/lib/pwn-unified-data';
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

const TAB_ICONS: Record<TabType, React.ReactNode> = {
  overview: <FileText size={12} />,
  prerequisites: <AlertCircle size={12} />,
  constraints: <AlertCircle size={12} />,
  blueprint: <Database size={12} />,
  precond: <AlertCircle size={12} />,
  exploits: <Target size={12} />,
  checklist: <ListChecks size={12} />,
  refs: <Link2 size={12} />,
  heap: <Layers size={12} />,
  resources: <BookOpen size={12} />,
  sessions: <FolderOpen size={12} />,
  recon: <Search size={12} />,
};

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
          <div className="pwn-inspector-title flex items-center gap-2">
            <Search size={16} className="text-cyan-400" />
            Pre-Pwn Recon
          </div>
        </div>
        <div className="pwn-inspector-content">
          <ReconWizard selectedTags={reconTags} onTagsChange={onReconTagsChange || (() => {})} />
          <div className="pwn-divider" />
          <ExploitRecommender selectedTags={reconTags} onSelectTechnique={onSelectTechniqueById || (() => {})} />
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
      recon: { label: 'Reconnaissance', color: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/40' },
      technique: { label: 'Technique', color: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/40' },
      mitigation: { label: 'Mitigation', color: 'bg-amber-500/15 text-amber-300 border-amber-500/40' },
      leaf: { label: 'Exploitation', color: 'bg-rose-500/15 text-rose-300 border-rose-500/40' },
    };
    const badge = badges[selectedNode.category];
    if (!badge) return null;

    return (
      <span className={`text-xs font-semibold px-2.5 py-1 rounded-md border ${badge.color}`}>{badge.label}</span>
    );
  };

  const renderTabContent = () => {
    if (hasKB && kbEntry) {
      switch (activeTab) {
        case 'overview':
          return (
            <div className="pwn-section space-y-4">
              <p className="pwn-section-content">{kbEntry.description}</p>
              <div className="pwn-card">
                <p className="pwn-card-title">Class</p>
                <p className="text-gray-300 text-sm">{kbEntry.class}</p>
              </div>
            </div>
          );

        case 'precond':
          return (
            <div className="pwn-section space-y-4">
              <div className="pwn-card">
                <p className="pwn-card-title">Summary</p>
                <p className="text-gray-300 text-sm">{kbEntry.preconditions.summary}</p>
              </div>
              <div className="pwn-card">
                <p className="pwn-card-title">Required Conditions</p>
                <ul className="space-y-2">
                  {kbEntry.preconditions.required.map((req, idx) => (
                    <li key={idx} className="text-gray-300 text-sm flex gap-2">
                      <span className="text-cyan-400 mt-0.5">›</span>
                      <span>{req}</span>
                    </li>
                  ))}
                </ul>
              </div>
              <div className="pwn-card">
                <p className="pwn-card-title">Detection Steps</p>
                <ol className="space-y-2">
                  {kbEntry.preconditions.detectionSteps.map((step, idx) => (
                    <li key={idx} className="text-gray-300 text-sm flex gap-2">
                      <span className="text-emerald-400 font-mono text-xs mt-0.5">{idx + 1}.</span>
                      <code className="text-gray-300 bg-slate-800/50 px-1.5 py-0.5 rounded text-xs">{step}</code>
                    </li>
                  ))}
                </ol>
              </div>
            </div>
          );

        case 'exploits':
          return (
            <div className="pwn-section space-y-4">
              {kbEntry.exploitationPaths.map((path, idx) => (
                <div key={idx} className="pwn-card space-y-3">
                  <div>
                    <p className="text-cyan-300 font-semibold text-sm">{path.name}</p>
                    <p className="text-gray-400 text-xs mt-1 leading-relaxed">{path.description}</p>
                  </div>
                  {path.steps && path.steps.length > 0 && (
                    <div>
                      <p className="text-xs text-amber-400 font-semibold mb-2 uppercase tracking-wider">Steps</p>
                      <ol className="space-y-1.5">
                        {path.steps.map((step, s) => (
                          <li key={s} className="text-gray-300 text-sm flex gap-2">
                            <span className="text-amber-400 font-mono text-xs mt-0.5">{s + 1}.</span>
                            <span>{step}</span>
                          </li>
                        ))}
                      </ol>
                    </div>
                  )}
                  {path.tools && path.tools.length > 0 && (
                    <div>
                      <p className="text-xs text-emerald-400 font-semibold mb-2 uppercase tracking-wider">Tools</p>
                      <div className="flex flex-wrap gap-1.5">
                        {path.tools.map((tool) => (
                          <span key={tool} className="px-2 py-0.5 bg-emerald-900/20 text-emerald-300 text-xs rounded-md border border-emerald-500/20">
                            {tool}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                  {path.codeSnippet && (
                    <div className="relative">
                      <pre className="pwn-code-block">
                        <code>{path.codeSnippet}</code>
                      </pre>
                      <button
                        onClick={() => handleCopy(path.codeSnippet!, `code-${idx}`)}
                        className="absolute top-2 right-2 p-1.5 bg-slate-700 hover:bg-slate-600 rounded-md text-xs transition-colors"
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
              <div className="pwn-card">
                <p className="pwn-card-title">Operator Workflow</p>
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
            <div className="pwn-section space-y-3">
              {kbEntry.references && kbEntry.references.length > 0 ? (
                kbEntry.references.map((ref, idx) => (
                  <div key={idx} className="pwn-card space-y-2">
                    {ref.tool && <p className="text-cyan-300 text-sm font-semibold">{ref.tool}</p>}
                    <p className="text-gray-300 text-sm leading-relaxed">{ref.description}</p>
                    {ref.url && (
                      <a
                        href={ref.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="pwn-ref-link"
                      >
                        Read More <ExternalLink size={12} />
                      </a>
                    )}
                  </div>
                ))
              ) : (
                <div className="pwn-empty-state">
                  <Link2 size={24} className="text-gray-600" />
                  <p className="pwn-empty-state-title">No References</p>
                  <p className="pwn-empty-state-desc">No references available for this technique yet.</p>
                </div>
              )}
            </div>
          );

        case 'heap':
          const heapRef = getHeapReferenceForTechnique(selectedNode.id);
          return heapRef ? (
            <div className="pwn-section space-y-4">
              <div className="pwn-card">
                <p className="pwn-card-title">Heap Technique</p>
                <p className="text-gray-300 font-semibold text-sm">{heapRef.name}</p>
              </div>
              <div className="pwn-card">
                <p className="pwn-card-title">Category</p>
                <p className="text-gray-300 text-sm">{heapRef.category.replace('-', ' ').toUpperCase()}</p>
              </div>
              <div className="pwn-card">
                <p className="pwn-card-title">Difficulty</p>
                <span className={`inline-flex px-2.5 py-1 rounded-md text-xs font-semibold ${
                  heapRef.difficulty === 'Expert' ? 'bg-red-900/30 text-red-300 border border-red-500/30' :
                  heapRef.difficulty === 'Hard' ? 'bg-orange-900/30 text-orange-300 border border-orange-500/30' :
                  heapRef.difficulty === 'Medium' ? 'bg-yellow-900/30 text-yellow-300 border border-yellow-500/30' :
                  'bg-green-900/30 text-green-300 border border-green-500/30'
                }`}>
                  {heapRef.difficulty}
                </span>
              </div>
              {heapRef.glibcVersions && (
                <div className="pwn-card">
                  <p className="pwn-card-title">glibc Versions</p>
                  <div className="flex flex-wrap gap-1.5">
                    {heapRef.glibcVersions.map((v) => (
                      <span key={v} className="px-2 py-0.5 bg-slate-800 text-gray-300 text-xs rounded-md border border-slate-600">
                        {v}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="pwn-empty-state">
              <Layers size={24} className="text-gray-600" />
              <p className="pwn-empty-state-title">No Heap Reference</p>
              <p className="pwn-empty-state-desc">No heap exploitation reference available for this technique.</p>
            </div>
          );

        case 'resources':
          const heapRefRes = getHeapReferenceForTechnique(selectedNode.id);
          return (
            <div className="pwn-section space-y-3">
              {heapRefRes && (
                <>
                  {heapRefRes.how2heapLink && (
                    <a
                      href={heapRefRes.how2heapLink}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="pwn-card hover:border-blue-500/40 transition-all group block"
                    >
                      <div className="flex items-center gap-2 mb-2">
                        <Github size={14} className="text-blue-400" />
                        <span className="text-sm font-semibold text-blue-300">shellphish/how2heap</span>
                        <ExternalLink size={10} className="opacity-50 group-hover:opacity-100 transition-opacity" />
                      </div>
                      <p className="text-xs text-gray-400">Exploiting the Heap</p>
                    </a>
                  )}
                  {heapRefRes.dhavalkapilChapter && (
                    <a
                      href={heapRefRes.dhavalkapilChapter}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="pwn-card hover:border-purple-500/40 transition-all group block"
                    >
                      <div className="flex items-center gap-2 mb-2">
                        <BookOpen size={14} className="text-purple-400" />
                        <span className="text-sm font-semibold text-purple-300">Heap Exploitation Guide</span>
                        <ExternalLink size={10} className="opacity-50 group-hover:opacity-100 transition-opacity" />
                      </div>
                      <p className="text-xs text-gray-400">By Dhavalkapil</p>
                    </a>
                  )}
                </>
              )}
              <div className="pwn-card">
                <p className="pwn-card-title">Exploitation Tips</p>
                <ul className="space-y-1.5 text-sm text-gray-400">
                  <li className="flex gap-2">
                    <span className="text-cyan-400">›</span>
                    <span>Leak heap addresses via info disclosure</span>
                  </li>
                  <li className="flex gap-2">
                    <span className="text-cyan-400">›</span>
                    <span>Use gdb breakpoints to inspect heap layout</span>
                  </li>
                  <li className="flex gap-2">
                    <span className="text-cyan-400">›</span>
                    <span>Test with ASLR disabled first</span>
                  </li>
                  <li className="flex gap-2">
                    <span className="text-cyan-400">›</span>
                    <span>Verify glibc version matches exploit</span>
                  </li>
                </ul>
              </div>
            </div>
          );

        case 'recon':
          return (
            <div className="pwn-section space-y-4">
              <ReconWizard selectedTags={reconTags} onTagsChange={onReconTagsChange || (() => {})} />
              <div className="pwn-divider" />
              <ExploitRecommender selectedTags={reconTags} onSelectTechnique={onSelectTechniqueById || (() => {})} />
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
                <ul className="pwn-section-content space-y-2">
                  {selectedNode.prerequisites.map((req, idx) => (
                    <li key={idx} className="flex gap-2">
                      <span className="text-cyan-400 flex-shrink-0 mt-0.5">›</span>
                      <span>{req}</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <div className="pwn-empty-state">
                  <AlertCircle size={24} className="text-gray-600" />
                  <p className="pwn-empty-state-title">No Prerequisites</p>
                  <p className="pwn-empty-state-desc">No specific prerequisites for this technique.</p>
                </div>
              )}
            </div>
          );

        case 'constraints':
          return (
            <div className="pwn-section">
              {selectedNode.constraints.length > 0 ? (
                <ul className="pwn-section-content space-y-2">
                  {selectedNode.constraints.map((constraint, idx) => (
                    <li key={idx} className="flex gap-2">
                      <span className="text-rose-400 flex-shrink-0 mt-0.5">•</span>
                      <span>{constraint}</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <div className="pwn-empty-state">
                  <AlertCircle size={24} className="text-gray-600" />
                  <p className="pwn-empty-state-title">No Constraints</p>
                  <p className="pwn-empty-state-desc">No constraints listed for this technique.</p>
                </div>
              )}
            </div>
          );

        case 'blueprint':
          return (
            <div className="pwn-section">
              <div className="relative">
                <pre className="pwn-code-block">
                  <code>{selectedNode.blueprint}</code>
                </pre>
                <button
                  onClick={() => handleCopy(selectedNode.blueprint, 'blueprint')}
                  className="absolute top-2 right-2 p-1.5 bg-slate-700 hover:bg-slate-600 rounded-md border border-slate-600 text-cyan-400 transition-colors"
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
            <div className="pwn-section space-y-4">
              <ReconWizard selectedTags={reconTags} onTagsChange={onReconTagsChange || (() => {})} />
              <div className="pwn-divider" />
              <ExploitRecommender selectedTags={reconTags} onSelectTechnique={onSelectTechniqueById || (() => {})} />
            </div>
          );

        case 'sessions':
          return (
            <div className="pwn-section">
              <p className="text-xs text-cyan-400 font-semibold mb-3 uppercase tracking-wider">Saved Sessions</p>
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
    prerequisites: 'Prereqs',
    constraints: 'Constraints',
    blueprint: 'Blueprint',
    precond: 'Preconditions',
    exploits: 'Exploits',
    checklist: 'Checklist',
    refs: 'References',
    heap: 'Heap',
    resources: 'Resources',
    sessions: 'Sessions',
    recon: 'Recon',
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
            title={tabLabels[tab]}
          >
            <span className="opacity-70">{TAB_ICONS[tab]}</span>
            <span>{tabLabels[tab]}</span>
          </button>
        ))}
      </div>

      <div className="pwn-inspector-content">{renderTabContent()}</div>
    </div>
  );
}
