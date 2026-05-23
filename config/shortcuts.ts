/**
 * Keyboard shortcuts configuration
 * Centralized definition of all keyboard shortcuts
 */

export interface KeyboardShortcutConfig {
  key: string;
  description: string;
  category: 'navigation' | 'search' | 'ui' | 'tree';
}

export const KEYBOARD_SHORTCUTS: KeyboardShortcutConfig[] = [
  // Navigation
  {
    key: '/',
    description: 'Focus search input',
    category: 'navigation',
  },
  {
    key: '?',
    description: 'Show keyboard help',
    category: 'navigation',
  },
  {
    key: 'Escape',
    description: 'Clear selection / Close modals',
    category: 'navigation',
  },

  // Search
  {
    key: 'Cmd+F / Ctrl+F',
    description: 'Open search (browser default)',
    category: 'search',
  },

  // UI
  {
    key: 'Cmd+P / Ctrl+P',
    description: 'Pin current technique',
    category: 'ui',
  },

  // Tree operations
  {
    key: 'Cmd+Shift+E / Ctrl+Shift+E',
    description: 'Expand all nodes',
    category: 'tree',
  },
  {
    key: 'Cmd+Shift+C / Ctrl+Shift+C',
    description: 'Collapse all nodes',
    category: 'tree',
  },
];

/**
 * Get shortcuts by category
 */
export function getShortcutsByCategory(
  category: KeyboardShortcutConfig['category']
): KeyboardShortcutConfig[] {
  return KEYBOARD_SHORTCUTS.filter(s => s.category === category);
}

/**
 * Get all shortcuts grouped by category
 */
export function getShortcutsGrouped(): Record<
  KeyboardShortcutConfig['category'],
  KeyboardShortcutConfig[]
> {
  return {
    navigation: getShortcutsByCategory('navigation'),
    search: getShortcutsByCategory('search'),
    ui: getShortcutsByCategory('ui'),
    tree: getShortcutsByCategory('tree'),
  };
}
