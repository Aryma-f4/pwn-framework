'use client';

import { Technique } from '@/lib/pwn-data';
import { PwnSearch } from './pwn-search';
import { FilterType } from '@/lib/pwn-filters';

interface PwnSidebarProps {
  onSearchChange: (matches: Set<string>, pathHighlight: Set<string>) => void;
  onFilterChange: (filterType: FilterType | null) => void;
  visibleNodeCount: number;
}

export function PwnSidebar({ onSearchChange, onFilterChange, visibleNodeCount }: PwnSidebarProps) {
  return (
    <div className="pwn-sidebar">
      {/* Search and Filters */}
      <PwnSearch onSearchChange={onSearchChange} onFilterChange={onFilterChange} />

      {/* Legend */}
      <div className="pwn-legend">
        <p className="text-xs font-mono text-gray-500 uppercase tracking-wider mb-3">Categories</p>

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
      <div className="px-4 py-3 border-t border-gray-700/50 text-xs text-gray-500 space-y-1">
        <div className="flex justify-between">
          <span>Visible Nodes:</span>
          <span className="text-cyan-400 font-mono">{visibleNodeCount}</span>
        </div>
        <p className="text-gray-600 pt-2">
          Double-click the canvas to reset zoom. Click nodes to explore details.
        </p>
      </div>
    </div>
  );
}
