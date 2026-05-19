'use client';

import { Technique } from '@/lib/pwn-data';
import { PwnSearch } from './pwn-search';
import { FilterType } from '@/lib/pwn-filters';
import { Pin, Search, Keyboard, HelpCircle } from 'lucide-react';

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
        <div className="space-y-2">
          <div className="flex items-center gap-1.5">
            <Pin size={10} className="text-cyan-400" />
            <span className="text-xs font-semibold text-cyan-400 uppercase tracking-wider">
              Pinned ({pinnedTechniques.size})
            </span>
          </div>
          <div className="space-y-1">
            {Array.from(pinnedTechniques).map((id) => (
              <div
                key={id}
                className="pwn-pinned-item"
              >
                <Pin size={10} className="text-cyan-500/50 flex-shrink-0" />
                <span className="truncate">{id.replace(/-/g, ' ').toUpperCase()}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Legend */}
      <div className="pwn-legend">
        <p className="pwn-legend-title">Categories</p>

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

      {/* Stats & Help */}
      <div className="mt-auto space-y-3">
        <div className="pwn-divider" />
        
        <div className="pwn-stats">
          <span className="text-muted-foreground">Visible Nodes</span>
          <span className="pwn-stats-value">{visibleNodeCount}</span>
        </div>

        <div className="space-y-1.5">
          <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Keyboard Shortcuts</p>
          <div className="space-y-1">
            <div className="pwn-shortcut-hint">
              <kbd className="pwn-shortcut-key">/</kbd>
              <span>to search</span>
            </div>
            <div className="pwn-shortcut-hint">
              <kbd className="pwn-shortcut-key">Esc</kbd>
              <span>to clear</span>
            </div>
            <div className="pwn-shortcut-hint">
              <kbd className="pwn-shortcut-key">?</kbd>
              <span>for help</span>
            </div>
            <div className="pwn-shortcut-hint">
              <kbd className="pwn-shortcut-key">Ctrl</kbd>
              <span>+</span>
              <kbd className="pwn-shortcut-key">P</kbd>
              <span>to pin</span>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
