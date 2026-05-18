'use client';

import { useState } from 'react';
import { Search, X } from 'lucide-react';
import { searchTechniques, FILTER_PRESETS, FilterType } from '@/lib/pwn-filters';
import { PWN_TECHNIQUES } from '@/lib/pwn-data';

interface PwnSearchProps {
  onSearchChange: (matches: Set<string>, pathHighlight: Set<string>) => void;
  onFilterChange: (filterType: FilterType | null) => void;
  searchInputRef?: React.RefObject<HTMLInputElement>;
}

export function PwnSearch({ onSearchChange, onFilterChange, searchInputRef }: PwnSearchProps) {
  const [query, setQuery] = useState('');
  const [activeFilter, setActiveFilter] = useState<FilterType | null>(null);

  const handleSearchChange = (newQuery: string) => {
    setQuery(newQuery);
    const { matches, pathHighlight } = searchTechniques(PWN_TECHNIQUES, newQuery);
    onSearchChange(matches, pathHighlight);
  };

  const handleFilterClick = (filterType: FilterType) => {
    const newFilter = activeFilter === filterType ? null : filterType;
    setActiveFilter(newFilter);
    onFilterChange(newFilter);
    // Clear search when changing filters
    setQuery('');
  };

  const handleClear = () => {
    setQuery('');
    onSearchChange(new Set(), new Set());
  };

  return (
    <div className="space-y-3">
      {/* Search Input */}
      <div className="relative">
        <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-cyan-500/60" />
        <input
          ref={searchInputRef}
          type="text"
          value={query}
          onChange={(e) => handleSearchChange(e.target.value)}
          placeholder="Search techniques... (/)"
          className="pwn-search-input pl-8 pr-7"
        />
        {query && (
          <button
            onClick={handleClear}
            className="absolute right-2.5 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300 transition-colors"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        )}
      </div>

      {/* Filter Presets */}
      <div className="space-y-1.5">
        <p className="text-xs font-mono text-gray-500 uppercase tracking-wider">Quick Filters</p>
        <div className="space-y-1">
          {FILTER_PRESETS.map((preset) => (
            <button
              key={preset.type}
              onClick={() => handleFilterClick(preset.type)}
              className={`pwn-filter-btn ${preset.type} ${activeFilter === preset.type ? 'active' : ''} w-full text-left`}
            >
              <div className="font-mono font-semibold text-xs">{preset.name}</div>
              <div className="text-xs opacity-75 leading-tight">{preset.description}</div>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
