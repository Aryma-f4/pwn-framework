'use client';

import { useState, useMemo } from 'react';
import { Technique, PWN_TECHNIQUES } from '@/lib/pwn-data';
import { filterByVulnerability, FilterType } from '@/lib/pwn-filters';
import { PwnTreeCanvas } from '@/components/pwn-tree-canvas';
import { PwnSidebar } from '@/components/pwn-sidebar';
import { PwnInspector } from '@/components/pwn-inspector';
import '@/styles/pwn-dashboard.css';

export default function PwnExploitationDashboard() {
  const [selectedNode, setSelectedNode] = useState<Technique | null>(null);
  const [searchMatches, setSearchMatches] = useState<Set<string>>(new Set());
  const [pathHighlight, setPathHighlight] = useState<Set<string>>(new Set());
  const [activeFilter, setActiveFilter] = useState<FilterType | null>(null);

  const filteredTechniques = useMemo(() => {
    return filterByVulnerability(PWN_TECHNIQUES, activeFilter);
  }, [activeFilter]);

  const visibleNodeCount = Object.keys(filteredTechniques).length;

  const handleSearchChange = (matches: Set<string>, paths: Set<string>) => {
    setSearchMatches(matches);
    setPathHighlight(paths);
  };

  const handleFilterChange = (filterType: FilterType | null) => {
    setActiveFilter(filterType);
    setSelectedNode(null);
  };

  return (
    <div className="pwn-container flex flex-col">
      <div className="flex flex-1 overflow-hidden">
        <PwnSidebar
          onSearchChange={handleSearchChange}
          onFilterChange={handleFilterChange}
          visibleNodeCount={visibleNodeCount}
        />

        <PwnTreeCanvas
          selectedNode={selectedNode}
          onNodeSelect={setSelectedNode}
          searchMatches={searchMatches}
          pathHighlight={pathHighlight}
          filteredTechniques={filteredTechniques}
        />

        <PwnInspector selectedNode={selectedNode} />
      </div>

      {/* Footer with GitHub Credit */}
      <div className="border-t border-slate-800 bg-slate-950 px-4 py-3 flex items-center justify-between text-xs text-gray-500">
        <div className="flex items-center gap-2">
          <span>Knowledge Base by</span>
          <a
            href="https://github.com/Aryma-f4/pwn-framework"
            target="_blank"
            rel="noopener noreferrer"
            className="text-cyan-400 hover:text-cyan-300 transition-colors flex items-center gap-1"
          >
            Aryma-f4/pwn-framework
            <svg className="w-3 h-3" fill="currentColor" viewBox="0 0 24 24">
              <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v 3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" />
            </svg>
          </a>
        </div>
        <div className="text-gray-600">
          Data Source: Master Binary Exploitation Decision & Knowledge Matrix v5.0
        </div>
      </div>
    </div>
  );
}
