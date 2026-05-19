'use client';

import { useState } from 'react';
import { Search, X, Filter } from 'lucide-react';
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
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-cyan-500/50" />
        <input
          ref={searchInputRef}
          type="text"
          value={query}
          onChange={(e) => handleSearchChange(e.target.value)}
          placeholder="Search techniques..."
          className="pwn-search-input pl-10 pr-9"
        />
        {query ? (
          <button
            onClick={handleClear}
            className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300 transition-colors p-0.5 rounded hover:bg-slate-700/50"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        ) : (
          <kbd className="absolute right-3 top-1/2 -translate-y-1/2 pwn-shortcut-key text-[0.6rem]">/</kbd>
        )}
      </div>

      {/* Filter Presets */}
      <div className="space-y-2">
        <div className="flex items-center gap-1.5">
          <Filter size={10} className="text-cyan-400" />
          <p className="text-xs font-semibold text-cyan-400 uppercase tracking-wider">Quick Filters</p>
        </div>
        <div className="space-y-1.5">
          {FILTER_PRESETS.map((preset) => (
            <button
              key={preset.type}
              onClick={() => handleFilterClick(preset.type)}
              className={`pwn-filter-btn ${preset.type} ${activeFilter === preset.type ? 'active' : ''}`}
            >
              <div className="font-semibold text-xs">{preset.name}</div>
              <div className="text-xs opacity-70 leading-tight mt-0.5">{preset.description}</div>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
