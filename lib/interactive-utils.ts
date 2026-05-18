// Interactive UI utilities for enhanced dashboard experience
export interface TooltipConfig {
  title: string;
  description: string;
  difficulty?: 'Easy' | 'Medium' | 'Hard' | 'Expert';
  tactics?: string[];
  relatedTechniques?: string[];
}

export interface KeyboardShortcut {
  key: string;
  description: string;
  action: string;
}

export const KEYBOARD_SHORTCUTS: KeyboardShortcut[] = [
  { key: '/', description: 'Focus search', action: 'search' },
  { key: 'Escape', description: 'Clear search & filters', action: 'clear' },
  { key: 'Enter', description: 'Confirm selection', action: 'confirm' },
  { key: 'ArrowUp', description: 'Select previous technique', action: 'prev' },
  { key: 'ArrowDown', description: 'Select next technique', action: 'next' },
  { key: '?', description: 'Show keyboard help', action: 'help' },
  { key: 'ctrl+f', description: 'Advanced filter modal', action: 'filter' },
  { key: 'ctrl+p', description: 'Pin/unpin technique', action: 'pin' },
];

export const TECHNIQUE_TOOLTIPS: Record<string, TooltipConfig> = {
  'fastbin-dup': {
    title: 'Fastbin Duplication',
    description: 'Exploit double-free to allocate the same chunk twice. Classic heap exploitation.',
    difficulty: 'Easy',
    tactics: ['Chunk Corruption', 'Memory Disclosure', 'Arbitrary Write'],
    relatedTechniques: ['fastbin-dup-into-stack', 'tcache-poisoning']
  },
  'fastbin-dup-into-stack': {
    title: 'Fastbin Dup into Stack',
    description: 'Double-free heap chunk to allocate memory in stack area. Enables stack manipulation.',
    difficulty: 'Medium',
    tactics: ['Stack Corruption', 'ROP Setup'],
    relatedTechniques: ['fastbin-dup', 'house-of-spirit']
  },
  'tcache-poisoning': {
    title: 'Tcache Poisoning',
    description: 'Corrupt tcache linked list to allocate arbitrary memory. Modern glibc exploitation.',
    difficulty: 'Medium',
    tactics: ['Use-After-Free', 'Arbitrary Allocation'],
    relatedTechniques: ['tcache-dup', 'house-of-einherjar']
  },
  'tcache-dup': {
    title: 'Tcache Duplicate Free',
    description: 'Free same chunk twice to tcache without checks. Glibc 2.26-2.29 vulnerability.',
    difficulty: 'Easy',
    tactics: ['Double-Free', 'Arbitrary Allocation'],
    relatedTechniques: ['tcache-poisoning', 'fastbin-dup']
  },
  'house-of-spirit': {
    title: 'House of Spirit',
    description: 'Create fake chunk on stack and free it to get stack allocation.',
    difficulty: 'Medium',
    tactics: ['Stack Overflow', 'Chunk Forgery'],
    relatedTechniques: ['house-of-lore', 'house-of-force']
  },
  'house-of-force': {
    title: 'House of Force',
    description: 'Corrupt top chunk size to allocate at arbitrary address. Powerful but complex.',
    difficulty: 'Hard',
    tactics: ['Top Chunk Corruption', 'Arbitrary Allocation'],
    relatedTechniques: ['house-of-spirit', 'house-of-einherjar']
  },
  'house-of-lore': {
    title: 'House of Lore',
    description: 'Corrupt small-bin backward pointer to allocate at arbitrary address.',
    difficulty: 'Hard',
    tactics: ['Bin Corruption', 'Unlink Exploitation'],
    relatedTechniques: ['house-of-einherjar', 'unsorted-bin-attack']
  },
  'unsorted-bin-attack': {
    title: 'Unsorted Bin Attack',
    description: 'Write large value to arbitrary address by corrupting unsorted bin.',
    difficulty: 'Medium',
    tactics: ['Bin Corruption', 'Arbitrary Write'],
    relatedTechniques: ['house-of-einherjar', 'house-of-lore']
  },
  'house-of-einherjar': {
    title: 'House of Einherjar',
    description: 'Forge chunk in freed memory via corrupted prev_size. Most complex technique.',
    difficulty: 'Expert',
    tactics: ['Coalescing Exploitation', 'Precision Offsets'],
    relatedTechniques: ['house-of-force', 'house-of-lore']
  },
  'large-bin-attack': {
    title: 'Large Bin Attack',
    description: 'Corrupt large-bin to write large values to multiple arbitrary addresses.',
    difficulty: 'Expert',
    tactics: ['Bin Corruption', 'Multi-target Write'],
    relatedTechniques: ['house-of-einherjar', 'unsorted-bin-attack']
  }
};

export const KEYBOARD_HELP = `
┌─────────────────────────────────────────────────┐
│         KEYBOARD SHORTCUTS & CONTROLS           │
├─────────────────────────────────────────────────┤
│ /            │ Focus search bar                  │
│ Escape       │ Clear all filters & search        │
│ Enter        │ Confirm node selection             │
│ ↑/↓          │ Navigate between techniques       │
│ Ctrl+F       │ Open advanced filter modal         │
│ Ctrl+P       │ Pin/unpin current technique       │
│ ?            │ Show this help dialog             │
│ Double-Click │ Expand/collapse node children     │
│ Hover        │ View technique tooltips           │
└─────────────────────────────────────────────────┘
`;

export const animationClasses = {
  nodeHover: 'node-hover-glow',
  nodeSelect: 'node-select-pulse',
  tooltipFadeIn: 'tooltip-fade-in',
  transitionSmooth: 'transition-all duration-300 ease-in-out'
};

export function createTooltipContent(technique: TooltipConfig): string {
  return `
    <div class="tooltip-header">${technique.title}</div>
    <p class="tooltip-desc">${technique.description}</p>
    ${technique.difficulty ? `<div class="tooltip-difficulty">${technique.difficulty}</div>` : ''}
    ${technique.tactics ? `<div class="tooltip-tactics">${technique.tactics.join(' • ')}</div>` : ''}
  `;
}
