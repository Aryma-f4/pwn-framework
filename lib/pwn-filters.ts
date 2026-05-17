import { Technique, PWN_TECHNIQUES } from './pwn-data';

export type FilterType = 'stack' | 'format' | 'heap' | 'sandbox';

export interface FilterPreset {
  name: string;
  type: FilterType;
  description: string;
  color: string;
}

export const FILTER_PRESETS: FilterPreset[] = [
  {
    name: 'Stack-based',
    type: 'stack',
    description: 'Buffer overflows and ROP exploits',
    color: 'from-emerald-500 to-emerald-600',
  },
  {
    name: 'Format Strings',
    type: 'format',
    description: 'Printf vulnerabilities',
    color: 'from-amber-500 to-amber-600',
  },
  {
    name: 'Heap-based',
    type: 'heap',
    description: 'Heap corruption and UAF',
    color: 'from-cyan-500 to-cyan-600',
  },
  {
    name: 'Sandbox Escape',
    type: 'sandbox',
    description: 'Container and browser breakouts',
    color: 'from-rose-500 to-rose-600',
  },
];

export const filterByVulnerability = (
  techniques: Record<string, Technique>,
  filterType: FilterType | null,
): Record<string, Technique> => {
  if (!filterType) return techniques;

  const filtered: Record<string, Technique> = {};

  Object.entries(techniques).forEach(([key, technique]) => {
    switch (filterType) {
      case 'stack':
        if (technique.stack.length > 0) filtered[key] = technique;
        break;
      case 'format':
        if (technique.format.length > 0) filtered[key] = technique;
        break;
      case 'heap':
        if (technique.heap.length > 0) filtered[key] = technique;
        break;
      case 'sandbox':
        if (technique.sandbox.length > 0) filtered[key] = technique;
        break;
    }
  });

  // Include root and all necessary parent nodes
  const includedIds = new Set(Object.keys(filtered));
  const allIds = new Set(Object.keys(techniques));

  // Find all ancestors of included nodes
  const addAncestors = (techId: string) => {
    if (includedIds.has(techId)) return;

    for (const [key, tech] of Object.entries(techniques)) {
      if (tech.children?.includes(techId)) {
        includedIds.add(key);
        addAncestors(key);
      }
    }
  };

  includedIds.forEach((id) => addAncestors(id));

  // Build result with all ancestors
  const result: Record<string, Technique> = {};
  includedIds.forEach((id) => {
    result[id] = techniques[id];
  });

  return result;
};

export const searchTechniques = (
  techniques: Record<string, Technique>,
  query: string,
): { matches: Set<string>; pathHighlight: Set<string> } => {
  const lowerQuery = query.toLowerCase();
  const matches = new Set<string>();
  const pathHighlight = new Set<string>();

  if (!query.trim()) {
    return { matches, pathHighlight };
  }

  // Find matching nodes
  Object.entries(techniques).forEach(([id, tech]) => {
    if (
      tech.name.toLowerCase().includes(lowerQuery) ||
      tech.description.toLowerCase().includes(lowerQuery) ||
      tech.blueprint.toLowerCase().includes(lowerQuery)
    ) {
      matches.add(id);
    }
  });

  // Highlight paths from matches to root
  const addAncestors = (techId: string) => {
    pathHighlight.add(techId);
    for (const [key, tech] of Object.entries(techniques)) {
      if (tech.children?.includes(techId)) {
        addAncestors(key);
      }
    }
  };

  matches.forEach((id) => addAncestors(id));

  return { matches, pathHighlight };
};

export const getFilterPresetColor = (filterType: FilterType): string => {
  const preset = FILTER_PRESETS.find((p) => p.type === filterType);
  return preset?.color || 'from-slate-500 to-slate-600';
};
