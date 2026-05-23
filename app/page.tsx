'use client';

import { useState, useMemo, useEffect, useRef, useCallback } from 'react';
import { Technique, PWN_TECHNIQUES } from '@/lib/pwn-data';
import { filterByVulnerability, FilterType } from '@/lib/pwn-filters';
import { getExploitRecommendations } from '@/lib/pwn-recon-data';
import { PwnTreeCanvas } from '@/components/pwn-tree-canvas';
import { PwnSidebar } from '@/components/pwn-sidebar';
import { PwnInspector } from '@/components/pwn-inspector';
import { KeyboardHelpModal } from '@/components/keyboard-help-modal';
import { WelcomeModal } from '@/components/exploit-workflow';
import { ResizablePanel } from '@/components/resizable-panel';
import { ErrorBoundary } from '@/components/error-boundary';
import { storage } from '@/lib/storage';
import { logger } from '@/lib/logger';
import '@/styles/pwn-dashboard.css';

export default function PwnExploitationDashboard() {
  const [selectedNode, setSelectedNode] = useState<Technique | null>(null);
  const [searchMatches, setSearchMatches] = useState<Set<string>>(new Set());
  const [pathHighlight, setPathHighlight] = useState<Set<string>>(new Set());
  const [activeFilter, setActiveFilter] = useState<FilterType | null>(null);
  const [showKeyboardHelp, setShowKeyboardHelp] = useState(false);
  const [showWelcome, setShowWelcome] = useState(() => {
    // Only show welcome on first visit using storage utility
    if (typeof window !== 'undefined') {
      const hasVisited = storage.get('pwn_welcomed');
      return !hasVisited;
    }
    return false;
  });
  const searchInputRef = useRef<HTMLInputElement>(null);
  const [pinnedTechniques, setPinnedTechniques] = useState<Set<string>>(new Set());
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [inspectorOpen, setInspectorOpen] = useState(false);
  const [isMobile, setIsMobile] = useState(false);
  const [reconTags, setReconTags] = useState<Set<string>>(new Set());
  const [currentPhase, setCurrentPhase] = useState<string>('recon');
  const [completedPhases, setCompletedPhases] = useState<Set<string>>(new Set());

  useEffect(() => {
    logger.info('PWN Framework dashboard initialized');
    const mediaQuery = window.matchMedia('(max-width: 768px)');
    const handleChange = (e: MediaQueryListEvent | MediaQueryList) => {
      setIsMobile(e.matches);
      if (!e.matches) {
        setSidebarOpen(false);
        setInspectorOpen(false);
      }
    };
    handleChange(mediaQuery);
    mediaQuery.addEventListener('change', handleChange);
    return () => mediaQuery.removeEventListener('change', handleChange);
  }, []);

  const filteredTechniques = useMemo(() => {
    let techniques = filterByVulnerability(PWN_TECHNIQUES, activeFilter);

    if (reconTags.size > 0) {
      const recommendations = getExploitRecommendations(reconTags);
      if (recommendations.length > 0) {
        const includedIds = new Set<string>();
        recommendations.forEach(r => includedIds.add(r.techniqueId));

        const addAncestors = (techId: string) => {
          for (const [key, tech] of Object.entries(PWN_TECHNIQUES)) {
            if (tech.children?.includes(techId)) {
              if (!includedIds.has(key)) {
                includedIds.add(key);
                addAncestors(key);
              }
            }
          }
        };
        Array.from(includedIds).forEach(id => addAncestors(id));

        const addDescendants = (techId: string) => {
          const tech = PWN_TECHNIQUES[techId];
          if (tech && tech.children) {
            tech.children.forEach(childId => {
              if (!includedIds.has(childId)) {
                includedIds.add(childId);
                addDescendants(childId);
              }
            });
          }
        };
        recommendations.forEach(r => addDescendants(r.techniqueId));

        const reconFiltered: Record<string, Technique> = {};
        includedIds.forEach(id => {
          if (techniques[id]) reconFiltered[id] = techniques[id];
        });
        
        techniques = reconFiltered;
      }
    }

    return techniques;
  }, [activeFilter, reconTags]);

  const visibleNodeCount = Object.keys(filteredTechniques).length;

  // Auto-detect phase based on selected node
  useEffect(() => {
    if (!selectedNode) return;
    const phaseMap: Record<string, string> = {
      root: 'recon',
      recon: 'recon',
      mitigation: 'bypass',
      technique: 'exploit',
      leaf: 'execute',
    };
    const newPhase = phaseMap[selectedNode.category] || 'recon';
    if (newPhase !== currentPhase) {
      setCurrentPhase(newPhase);
    }
  }, [selectedNode?.id]);

  const handleSearchChange = (matches: Set<string>, paths: Set<string>) => {
    setSearchMatches(matches);
    setPathHighlight(paths);
  };

  const handleFilterChange = (filterType: FilterType | null) => {
    setActiveFilter(filterType);
    setSelectedNode(null);
  };

  const handlePhaseChange = (phaseId: string) => {
    setCurrentPhase(phaseId);
  };

  const handleTogglePhase = (phaseId: string) => {
    setCompletedPhases(prev => {
      const next = new Set(prev);
      if (next.has(phaseId)) next.delete(phaseId);
      else next.add(phaseId);
      return next;
    });
  };

  const closeMobileOverlays = useCallback(() => {
    setSidebarOpen(false);
    setInspectorOpen(false);
  }, []);

  const handleNodeSelect = useCallback((technique: Technique) => {
    setSelectedNode(technique);
    if (isMobile) {
      setInspectorOpen(true);
    }
  }, [isMobile]);

  const handleSelectTechniqueById = useCallback((techniqueId: string) => {
    const technique = PWN_TECHNIQUES[techniqueId];
    if (technique) {
      setSelectedNode(technique);
      if (isMobile) {
        setInspectorOpen(true);
      }
    }
  }, [isMobile]);

  const handleStartReconFromWelcome = useCallback(() => {
    setShowWelcome(false);
    setSidebarOpen(true);
  }, []);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === '/' && !e.ctrlKey && !e.metaKey) {
        e.preventDefault();
        if (isMobile) {
          setSidebarOpen(true);
        }
        searchInputRef.current?.focus();
      }
      
      if (e.key === 'Escape') {
        e.preventDefault();
        if (sidebarOpen || inspectorOpen) {
          closeMobileOverlays();
        } else {
          setSelectedNode(null);
          setActiveFilter(null);
          setSearchMatches(new Set());
          setPathHighlight(new Set());
          searchInputRef.current?.blur();
        }
      }
      
      if (e.key === '?' && !e.ctrlKey && !e.metaKey) {
        e.preventDefault();
        setShowKeyboardHelp(true);
      }
      
      if ((e.ctrlKey || e.metaKey) && e.key === 'p') {
        e.preventDefault();
        if (selectedNode) {
          const newPinned = new Set(pinnedTechniques);
          if (newPinned.has(selectedNode.id)) {
            newPinned.delete(selectedNode.id);
          } else {
            newPinned.add(selectedNode.id);
          }
          setPinnedTechniques(newPinned);
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [selectedNode, pinnedTechniques, isMobile, sidebarOpen, inspectorOpen, closeMobileOverlays]);

  useEffect(() => {
    if (reconTags.size === 0) {
      if (searchInputRef.current?.value === '') {
        setSearchMatches(new Set());
        setPathHighlight(new Set());
      }
      return;
    }

    const recommendations = getExploitRecommendations(reconTags);
    const matches = new Set<string>();
    const paths = new Set<string>();

    recommendations.forEach(r => matches.add(r.techniqueId));

    const addAncestors = (techId: string) => {
      paths.add(techId);
      for (const [key, tech] of Object.entries(PWN_TECHNIQUES)) {
        if (tech.children?.includes(techId)) {
          addAncestors(key);
        }
      }
    };

    const addDescendants = (techId: string) => {
      paths.add(techId);
      const tech = PWN_TECHNIQUES[techId];
      if (tech && tech.children) {
        tech.children.forEach(childId => {
          addDescendants(childId);
        });
      }
    };

    matches.forEach(id => {
      addAncestors(id);
      addDescendants(id);
    });

    setSearchMatches(matches);
    setPathHighlight(paths);
  }, [reconTags]);

  return (
    <ErrorBoundary>
      <>
        <WelcomeModal isOpen={showWelcome} onClose={() => setShowWelcome(false)} onStartRecon={handleStartReconFromWelcome} />
        <KeyboardHelpModal isOpen={showKeyboardHelp} onClose={() => setShowKeyboardHelp(false)} />
        <div className="pwn-container">
        {/* Header */}
        <header className="pwn-header">
          <div className="flex items-center gap-3">
            <div className="pwn-logo">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M12 2L2 7L12 12L22 7L12 2Z" fill="currentColor" fillOpacity="0.2"/>
                <path d="M2 17L12 22L22 17" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                <path d="M2 12L12 17L22 12" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
            </div>
            <div>
              <h1 className="pwn-header-title">PWN Framework</h1>
              <p className="pwn-header-subtitle">Binary Exploitation Decision Tree</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowWelcome(true)}
              className="pwn-header-btn"
              title="Show welcome guide"
            >
              <span className="hidden sm:inline">Guide</span>
              <span className="sm:hidden">?</span>
            </button>
            <button
              onClick={() => setShowKeyboardHelp(true)}
              className="pwn-header-btn"
              title="Keyboard shortcuts (?)"
            >
              <span className="hidden sm:inline">Shortcuts</span>
              <span className="sm:hidden">?</span>
            </button>
            <a
              href="https://github.com/Aryma-f4/pwn-framework"
              target="_blank"
              rel="noopener noreferrer"
              className="pwn-header-btn"
              title="View on GitHub"
            >
              <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
              </svg>
            </a>
          </div>
        </header>

        {/* Mobile toggle buttons */}
        <button
          className="pwn-mobile-toggle left"
          onClick={() => { setSidebarOpen(!sidebarOpen); setInspectorOpen(false); }}
          aria-label="Toggle sidebar"
        >
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
            <line x1="3" y1="6" x2="21" y2="6"/>
            <line x1="3" y1="12" x2="21" y2="12"/>
            <line x1="3" y1="18" x2="21" y2="18"/>
          </svg>
        </button>
        <button
          className="pwn-mobile-toggle right"
          onClick={() => { setInspectorOpen(!inspectorOpen); setSidebarOpen(false); }}
          aria-label="Toggle inspector"
        >
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
            <rect x="3" y="3" width="18" height="18" rx="2"/>
            <line x1="9" y1="3" x2="9" y2="21"/>
          </svg>
        </button>

        {/* Mobile overlay backdrop */}
        <div 
          className={`pwn-mobile-overlay ${(sidebarOpen || inspectorOpen) ? 'visible' : ''}`}
          onClick={closeMobileOverlays}
        />

        <div className="pwn-main-content">
          <div className={`pwn-sidebar ${sidebarOpen ? 'mobile-open' : ''}`}>
            <PwnSidebar
              onSearchChange={handleSearchChange}
              onFilterChange={handleFilterChange}
              visibleNodeCount={visibleNodeCount}
              searchInputRef={searchInputRef}
              pinnedTechniques={pinnedTechniques}
              currentPhase={currentPhase}
              onPhaseChange={handlePhaseChange}
              completedPhases={completedPhases}
              onTogglePhase={handleTogglePhase}
            />
          </div>

          <PwnTreeCanvas
            selectedNode={selectedNode}
            onNodeSelect={handleNodeSelect}
            searchMatches={searchMatches}
            pathHighlight={pathHighlight}
            filteredTechniques={filteredTechniques}
          />

          {!isMobile ? (
            <ResizablePanel 
              initialWidth={420}
              minWidth={300}
              maxWidth={700}
              position="right"
            >
              <PwnInspector
                selectedNode={selectedNode}
                reconTags={reconTags}
                onReconTagsChange={setReconTags}
                onSelectTechniqueById={handleSelectTechniqueById}
              />
            </ResizablePanel>
          ) : (
            <div className={`pwn-inspector-wrapper ${inspectorOpen ? 'mobile-open' : ''}`}>
              <PwnInspector
                selectedNode={selectedNode}
                reconTags={reconTags}
                onReconTagsChange={setReconTags}
                onSelectTechniqueById={handleSelectTechniqueById}
              />
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="pwn-footer">
          <div className="flex items-center gap-2">
            <span>Knowledge Base by</span>
            <a
              href="https://github.com/Aryma-f4/pwn-framework"
              target="_blank"
              rel="noopener noreferrer"
              className="transition-colors flex items-center gap-1"
            >
              Aryma-f4/pwn-framework
              <svg className="w-3 h-3" fill="currentColor" viewBox="0 0 24 24">
                <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" />
              </svg>
            </a>
          </div>
          <div>
            Data Source: Master Binary Exploitation Decision &amp; Knowledge Matrix v5.0 + how2heap
          </div>
        </div>
        </div>
      </>
    </ErrorBoundary>
  );
}