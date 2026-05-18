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
    <div className="space-y-4 p-4 border-b border-gray-700/50">
      {/* Search Input */}
      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-cyan-500/60" />
        <input
          ref={searchInputRef}
          type="text"
          value={query}
          onChange={(e) => handleSearchChange(e.target.value)}
          placeholder="Search techniques... (press / to focus)"
          className="pwn-search-input pl-9 pr-8"
        />
        {query && (
          <button
            onClick={handleClear}
            className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        )}
      </div>

      {/* Filter Presets */}
      <div className="space-y-2">
        <p className="text-xs font-mono text-gray-500 uppercase tracking-wider">Quick Filters</p>
        <div className="space-y-1.5">
          {FILTER_PRESETS.map((preset) => (
            <button
              key={preset.type}
              onClick={() => handleFilterClick(preset.type)}
              className={`pwn-filter-btn ${preset.type} ${activeFilter === preset.type ? 'active' : ''} w-full text-left`}
            >
              <div className="font-mono font-semibold">{preset.name}</div>
              <div className="text-xs opacity-75">{preset.description}</div>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
