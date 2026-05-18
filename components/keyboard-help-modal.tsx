'use client';

import { useEffect } from 'react';
import { X } from 'lucide-react';
import { KEYBOARD_SHORTCUTS } from '@/lib/interactive-utils';

interface KeyboardHelpModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export function KeyboardHelpModal({ isOpen, onClose }: KeyboardHelpModalProps) {
  useEffect(() => {
    if (!isOpen) return;

    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };

    window.addEventListener('keydown', handleEscape);
    return () => window.removeEventListener('keydown', handleEscape);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <div className="keyboard-help-modal" onClick={onClose}>
      <div className="keyboard-help-content" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-4">
          <div className="keyboard-help-title">Keyboard Shortcuts</div>
          <button
            onClick={onClose}
            className="text-gray-500 hover:text-gray-300 transition-colors"
          >
            <X size={20} />
          </button>
        </div>

        <div className="space-y-3 max-h-96 overflow-y-auto">
          {KEYBOARD_SHORTCUTS.map((shortcut, idx) => (
            <div key={idx} className="keyboard-help-item">
              <div className="flex items-center gap-2">
                <span className="keyboard-help-key">{shortcut.key}</span>
                <span className="keyboard-help-desc">{shortcut.description}</span>
              </div>
            </div>
          ))}
        </div>

        <div className="mt-4 pt-4 border-t border-slate-700 text-xs text-gray-500">
          Click outside or press Escape to close
        </div>
      </div>
    </div>
  );
}
