'use client';

import { Technique } from '@/lib/pwn-data';
import { PwnSearch } from './pwn-search';
import { FilterType } from '@/lib/pwn-filters';
import { Pin } from 'lucide-react';

interface PwnSidebarProps {
  onSearchChange: (matches: Set<string>, pathHighlight: Set<string>) => void;
  onFilterChange: (filterType: FilterType | null) => void;
  visibleNodeCount: number;
  searchInputRef?: React.RefObject<HTMLInputElement>;
  pinnedTechniques?: Set<string>;
}

export function PwnSidebar({ 
  onSearchChange, 
  onFilterChange, 
  visibleNodeCount,
  searchInputRef,
  pinnedTechniques = new Set()
}: PwnSidebarProps) {
  return (
    <>
      {/* Search and Filters */}
      <PwnSearch 
        onSearchChange={onSearchChange} 
        onFilterChange={onFilterChange}
        searchInputRef={searchInputRef}
      />

      {/* Pinned Techniques */}
      {pinnedTechniques.size > 0 && (
        <div className="px-2 py-2 border-b border-gray-700/30">
          <p className="text-xs font-mono text-cyan-400 uppercase tracking-wider mb-1.5 flex items-center gap-1.5">
            <Pin size={10} /> Pinned ({pinnedTechniques.size})
          </p>
          <div className="space-y-0.5">
            {Array.from(pinnedTechniques).map((id) => (
              <div
                key={id}
                className="text-xs bg-slate-800/50 border border-cyan-500/20 rounded px-2 py-0.5 text-gray-300 hover:text-cyan-300 transition-colors truncate"
              >
                {id.replace(/-/g, ' ').toUpperCase()}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Legend */}
      <div className="pwn-legend">
        <p className="text-xs font-mono text-gray-500 uppercase tracking-wider mb-2">Categories</p>

        <div className="pwn-legend-item">
          <div className="pwn-legend-dot bg-gray-100" />
          <span className="pwn-legend-label">Root Entry</span>
        </div>

        <div className="pwn-legend-item">
          <div className="pwn-legend-dot bg-emerald-500" />
          <span className="pwn-legend-label">Reconnaissance</span>
        </div>

        <div className="pwn-legend-item">
          <div className="pwn-legend-dot bg-cyan-500" />
          <span className="pwn-legend-label">Techniques</span>
        </div>

        <div className="pwn-legend-item">
          <div className="pwn-legend-dot bg-amber-500" />
          <span className="pwn-legend-label">Mitigations</span>
        </div>

        <div className="pwn-legend-item">
          <div className="pwn-legend-dot bg-rose-500" />
          <span className="pwn-legend-label">Exploitation</span>
        </div>
      </div>

      {/* Stats */}
      <div className="px-2 py-2 border-t border-gray-700/30 text-xs text-gray-500 space-y-0.5 mt-auto">
        <div className="flex justify-between">
          <span>Visible Nodes:</span>
          <span className="text-cyan-400 font-mono">{visibleNodeCount}</span>
        </div>
        <p className="text-gray-600 pt-1 text-xs leading-relaxed">
          <span className="block">Press <code className="bg-slate-800 px-1 rounded text-cyan-400 font-mono text-xs">?</code> for help</span>
          <span className="block">Ctrl+P to pin techniques</span>
          <span className="block">/ to search, Esc to clear</span>
        </p>
      </div>
    </>
  );
}
