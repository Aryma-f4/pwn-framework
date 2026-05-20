'use client';

import { useState, useEffect, useMemo } from 'react';
import { Copy, Check, ExternalLink, Github, BookOpen, Search, AlertCircle, FileText, ListChecks, Link2, Database, Layers, Target, FolderOpen, ChevronRight, Zap, Shield, Eye, Crosshair, Flag } from 'lucide-react';
import { Technique } from '@/lib/pwn-data';
import { getTechniqueKB } from '@/lib/pwn-unified-data';
import { getHeapReferenceForTechnique } from '@/lib/heap-reference-mapping';
import { InteractiveChecklist } from './interactive-checklist';
import { SessionManager } from './session-manager';
import { useSessions, ChecklistItem } from '@/lib/use-sessions';
import { ReconWizard } from './recon-wizard';
import { ExploitRecommender } from './exploit-recommender';
import { TECHNIQUE_TOOLTIPS } from '@/lib/interactive-utils';

interface PwnInspectorProps {
  selectedNode: Technique | null;
  reconTags?: Set<string>;
  onReconTagsChange?: (tags: Set<string>) => void;
  onSelectTechniqueById?: (techniqueId: string) => void;
}

type TabType = 'overview' | 'prerequisites' | 'constraints' | 'blueprint' | 'precond' | 'exploits' | 'checklist' | 'refs' | 'heap' | 'resources' | 'sessions' | 'recon';

const CATEGORY_PHASE_MAP: Record<string, string> = {
  root: 'recon',
  recon: 'recon',
  mitigation: 'bypass',
  technique: 'exploit',
  leaf: 'execute',
  setup: 'recon',
};

function getDifficultyBadge(category: string, hasKB: boolean) {
  if (category === 'root') return null;
  if (category === 'recon') return { label: 'Recon', cls: 'beginner' };
  if (category === 'mitigation') return { label: 'Defense', cls: 'intermediate' };
  if (category === 'technique') return { label: 'Attack', cls: 'advanced' };
  if (category === 'leaf') return { label: 'Exploit', cls: 'expert' };
  if (category === 'setup') return { label: 'Setup', cls: 'beginner' };
  return null;
}

function getPhaseTag(phase: string) {
  const phases: Record<string, { label: string; cls: string }> = {
    recon: { label: 'Phase 1: Recon', cls: 'recon' },
    vuln: { label: 'Phase 2: Vuln ID', cls: 'vuln' },
    bypass: { label: 'Phase 3: Bypass', cls: 'bypass' },
    exploit: { label: 'Phase 4: Exploit', cls: 'exploit' },
    execute: { label: 'Phase 5: Pwn', cls: 'execute' },
  };
  return phases[phase] || null;
}

function getNextStepsForNode(node: Technique): { step: string; phase: string; id?: string }[] {
  const steps: { step: string; phase: string; id?: string }[] = [];
  const phase = CATEGORY_PHASE_MAP[node.category] || 'recon';

  if (node.category === 'root' || node.category === 'recon') {
    steps.push({ step: 'Run checksec on the binary', phase: 'recon' });
    steps.push({ step: 'Identify the vulnerability type', phase: 'vuln' });
    if (node.children && node.children.length > 0) {
      steps.push({ step: `Explore ${node.children.length} sub-techniques`, phase: 'exploit', id: node.children[0] });
    }
  } else if (node.category === 'setup') {
    steps.push({ step: 'Follow the installation steps below', phase: 'recon' });
    steps.push({ step: 'Verify tool works with test binary', phase: 'recon' });
  } else if (node.category === 'mitigation') {
    steps.push({ step: 'Check if this protection is enabled', phase: 'recon' });
    steps.push({ step: 'Find a bypass strategy', phase: 'bypass' });
    if (node.children && node.children.length > 0) {
      steps.push({ step: `Try ${node.children[0].replace(/-/g, ' ')}`, phase: 'bypass', id: node.children[0] });
    }
  } else if (node.category === 'technique') {
    steps.push({ step: 'Verify preconditions are met', phase: 'exploit' });
    steps.push({ step: 'Review exploitation paths below', phase: 'exploit' });
    if (node.children && node.children.length > 0) {
      steps.push({ step: `Choose an execution path`, phase: 'exploit', id: node.children[0] });
    }
  } else if (node.category === 'leaf') {
    steps.push({ step: 'Build the exploit payload', phase: 'execute' });
    steps.push({ step: 'Test locally with ASLR off', phase: 'execute' });
    steps.push({ step: 'Send to remote target', phase: 'execute' });
  }

  return steps;
}

const TAB_ICONS: Record<TabType, React.ReactNode> = {
  overview: <FileText size={12} />,
  prerequisites: <AlertCircle size={12} />,
  constraints: <AlertCircle size={12} />,
  blueprint: <Database size={12} />,
  precond: <Eye size={12} />,
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
  
  useEffect(() => {
    if (selectedNode && selectedNode.id !== 'root' && isLoaded) {
      const activeSession = getActiveSession();
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

  // Reset to overview tab when node changes
  useEffect(() => {
    setActiveTab('overview');
  }, [selectedNode?.id]);

  const nextSteps = useMemo(() => {
    if (!selectedNode) return [];
    return getNextStepsForNode(selectedNode);
  }, [selectedNode]);

  const handleNextStepClick = (stepId?: string) => {
    if (stepId && onSelectTechniqueById) {
      onSelectTechniqueById(stepId);
    }
  };

  if (!selectedNode || selectedNode.id === 'root') {
    return (
      <div className="pwn-inspector">
        <div className="pwn-inspector-header">
          <div className="pwn-inspector-title flex items-center gap-2">
            <Eye size={16} className="text-cyan-400" />
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

  const kbEntry = getTechniqueKB(selectedNode.id);
  const hasKB = !!kbEntry;
  const difficultyBadge = getDifficultyBadge(selectedNode.category, hasKB);
  const phase = CATEGORY_PHASE_MAP[selectedNode.category] || 'recon';
  const phaseTag = getPhaseTag(phase);
  const tooltip = TECHNIQUE_TOOLTIPS[selectedNode.id];

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

              {/* Next Steps */}
              {nextSteps.length > 0 && (
                <div className="pwn-card">
                  <div className="flex items-center gap-1.5 mb-2.5">
                    <ChevronRight size={12} className="text-cyan-400" />
                    <p className="pwn-card-title mb-0">Recommended Next Steps</p>
                  </div>
                  <div className="pwn-next-steps">
                    {nextSteps.map((step, idx) => (
                      <button
                        key={idx}
                        onClick={() => handleNextStepClick(step.id)}
                        className={`pwn-next-step-item ${step.id ? 'cursor-pointer' : 'cursor-default'}`}
                      >
                        <span className={`pwn-next-step-num ${step.phase}`}>{idx + 1}</span>
                        <div className="flex-1 text-left">
                          <span className="text-xs text-gray-300">{step.step}</span>
                        </div>
                        {step.id && <ChevronRight size={12} className="text-gray-500 flex-shrink-0" />}
                      </button>
                    ))}
                  </div>
                </div>
              )}
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
              {kbEntry.preconditions.offsetDiscovery && Object.keys(kbEntry.preconditions.offsetDiscovery).length > 0 && (
                <div className="pwn-card">
                  <p className="pwn-card-title">Offset Discovery</p>
                  <div className="space-y-2">
                    {Object.entries(kbEntry.preconditions.offsetDiscovery).map(([tool, cmd]) => (
                      <div key={tool} className="flex items-start gap-2">
                        <span className="text-amber-400 text-xs font-mono">{tool}:</span>
                        <code className="text-gray-300 bg-slate-800/50 px-1.5 py-0.5 rounded text-xs flex-1">{cmd}</code>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          );

        case 'exploits':
          return (
            <div className="pwn-section space-y-4">
              {kbEntry.exploitationPaths.map((path, idx) => (
                <div key={idx} className="pwn-card space-y-3">
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <span className={`pwn-difficulty-badge ${idx === 0 ? 'intermediate' : idx === 1 ? 'advanced' : 'expert'}`}>
                        Path {idx + 1}
                      </span>
                      <p className="text-cyan-300 font-semibold text-sm">{path.name}</p>
                    </div>
                    <p className="text-gray-400 text-xs mt-1 leading-relaxed">{path.description}</p>
                  </div>
                  {path.applicableLibc && (
                    <div className="flex items-center gap-1.5">
                      <span className="text-xs text-gray-500 font-mono">libc:</span>
                      <span className="px-1.5 py-0.5 bg-purple-900/20 text-purple-300 text-xs rounded-md border border-purple-500/20">{path.applicableLibc}</span>
                    </div>
                  )}
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
          const completedCount = activeSession?.checklist.filter(c => c.completed).length || 0;
          const totalCount = activeSession?.checklist.length || 0;
          const progress = totalCount > 0 ? (completedCount / totalCount) * 100 : 0;

          return (
            <div className="pwn-section space-y-4">
              {activeSession && totalCount > 0 && (
                <div className="flex items-center gap-2 mb-1">
                  <div className="flex-1 h-1.5 bg-slate-900 rounded-full overflow-hidden border border-slate-800">
                    <div 
                      className="h-full bg-gradient-to-r from-emerald-500 to-cyan-500 transition-all duration-500"
                      style={{ width: `${progress}%` }}
                    />
                  </div>
                  <span className="text-xs font-mono text-cyan-400">{completedCount}/{totalCount}</span>
                </div>
              )}
              <div className="pwn-card">
                <div className="flex items-center gap-1.5 mb-2">
                  <ListChecks size={12} className="text-cyan-400" />
                  <p className="pwn-card-title mb-0">Operator Workflow</p>
                </div>
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
      switch (activeTab) {
        case 'overview':
          return (
            <div className="pwn-section space-y-4">
              <p className="pwn-section-content">{selectedNode.description}</p>

              {/* Next Steps for non-KB nodes */}
              {nextSteps.length > 0 && (
                <div className="pwn-card">
                  <div className="flex items-center gap-1.5 mb-2.5">
                    <ChevronRight size={12} className="text-cyan-400" />
                    <p className="pwn-card-title mb-0">Next Steps</p>
                  </div>
                  <div className="pwn-next-steps">
                    {nextSteps.map((step, idx) => (
                      <button
                        key={idx}
                        onClick={() => handleNextStepClick(step.id)}
                        className={`pwn-next-step-item ${step.id ? 'cursor-pointer' : 'cursor-default'}`}
                      >
                        <span className={`pwn-next-step-num ${step.phase}`}>{idx + 1}</span>
                        <div className="flex-1 text-left">
                          <span className="text-xs text-gray-300">{step.step}</span>
                        </div>
                        {step.id && <ChevronRight size={12} className="text-gray-500 flex-shrink-0" />}
                      </button>
                    ))}
                  </div>
                </div>
              )}
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
        <div className="flex items-center gap-2 flex-wrap">
          <div className="pwn-inspector-title">{selectedNode.name}</div>
          {difficultyBadge && (
            <span className={`pwn-difficulty-badge ${difficultyBadge.cls}`}>
              {difficultyBadge.label}
            </span>
          )}
        </div>
        <div className="mt-2 flex items-center gap-2 flex-wrap">
          {getCategoryBadge()}
          {phaseTag && (
            <span className={`pwn-phase-tag ${phaseTag.cls}`}>
              {phaseTag.label}
            </span>
          )}
        </div>
        {tooltip && (
          <p className="text-xs text-gray-500 mt-1.5 leading-relaxed">{tooltip.description}</p>
        )}
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