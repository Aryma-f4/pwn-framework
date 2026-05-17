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
    <div className="pwn-container">
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
  );
}
