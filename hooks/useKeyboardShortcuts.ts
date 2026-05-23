/**
 * Custom hook for keyboard shortcuts handling
 * Centralizes all keyboard event logic
 */

import { useEffect, useCallback } from 'react';
import { logger } from '@/lib/logger';

export interface KeyboardShortcutHandlers {
  onSearch?: () => void;
  onEscape?: () => void;
  onHelp?: () => void;
  onPin?: () => void;
  onExpandAll?: () => void;
  onCollapseAll?: () => void;
}

export interface KeyboardShortcut {
  key: string;
  description: string;
  handler: () => void;
}

export function useKeyboardShortcuts(handlers: KeyboardShortcutHandlers) {
  /**
   * Handle keyboard events
   */
  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      // Ignore if user is typing in an input
      const target = e.target as HTMLElement;
      const isInput =
        target.tagName === 'INPUT' ||
        target.tagName === 'TEXTAREA' ||
        target.contentEditable === 'true';

      // Search (/)
      if (e.key === '/' && !e.ctrlKey && !e.metaKey && !isInput) {
        e.preventDefault();
        handlers.onSearch?.();
        logger.debug('Keyboard shortcut triggered: Search');
      }

      // Escape
      if (e.key === 'Escape') {
        e.preventDefault();
        handlers.onEscape?.();
        logger.debug('Keyboard shortcut triggered: Escape');
      }

      // Help (?)
      if (e.key === '?' && !e.ctrlKey && !e.metaKey && !isInput) {
        e.preventDefault();
        handlers.onHelp?.();
        logger.debug('Keyboard shortcut triggered: Help');
      }

      // Pin (Cmd+P or Ctrl+P)
      if ((e.ctrlKey || e.metaKey) && e.key === 'p' && !isInput) {
        e.preventDefault();
        handlers.onPin?.();
        logger.debug('Keyboard shortcut triggered: Pin');
      }

      // Expand all (Cmd+Shift+E or Ctrl+Shift+E)
      if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === 'e' && !isInput) {
        e.preventDefault();
        handlers.onExpandAll?.();
        logger.debug('Keyboard shortcut triggered: Expand All');
      }

      // Collapse all (Cmd+Shift+C or Ctrl+Shift+C)
      if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === 'c' && !isInput) {
        e.preventDefault();
        handlers.onCollapseAll?.();
        logger.debug('Keyboard shortcut triggered: Collapse All');
      }
    },
    [handlers]
  );

  useEffect(() => {
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [handleKeyDown]);

  /**
   * Get all available shortcuts
   */
  const getShortcuts = useCallback((): KeyboardShortcut[] => {
    return [
      {
        key: '/',
        description: 'Focus search',
        handler: handlers.onSearch || (() => {}),
      },
      {
        key: '?',
        description: 'Show keyboard help',
        handler: handlers.onHelp || (() => {}),
      },
      {
        key: 'Escape',
        description: 'Clear selection / Close modals',
        handler: handlers.onEscape || (() => {}),
      },
      {
        key: 'Cmd+P',
        description: 'Pin current technique',
        handler: handlers.onPin || (() => {}),
      },
      {
        key: 'Cmd+Shift+E',
        description: 'Expand all nodes',
        handler: handlers.onExpandAll || (() => {}),
      },
      {
        key: 'Cmd+Shift+C',
        description: 'Collapse all nodes',
        handler: handlers.onCollapseAll || (() => {}),
      },
    ];
  }, [handlers]);

  return {
    getShortcuts,
  };
}
