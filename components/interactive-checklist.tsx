'use client';

import { useState } from 'react';
import { Check, Plus, Trash2, Edit2, Save, X } from 'lucide-react';
import { ChecklistItem } from '@/lib/use-sessions';

interface InteractiveChecklistProps {
  items: ChecklistItem[];
  onItemToggle: (itemId: string, completed: boolean) => void;
  onItemAdd?: (text: string) => void;
  onItemDelete?: (itemId: string) => void;
  onItemUpdate?: (itemId: string, text: string) => void;
  readOnly?: boolean;
}

export function InteractiveChecklist({
  items,
  onItemToggle,
  onItemAdd,
  onItemDelete,
  onItemUpdate,
  readOnly = false,
}: InteractiveChecklistProps) {
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editText, setEditText] = useState('');
  const [newItemText, setNewItemText] = useState('');

  const handleEdit = (item: ChecklistItem) => {
    setEditingId(item.id);
    setEditText(item.text);
  };

  const handleSave = (itemId: string) => {
    if (editText.trim() && onItemUpdate) {
      onItemUpdate(itemId, editText.trim());
    }
    setEditingId(null);
    setEditText('');
  };

  const handleAddItem = () => {
    if (newItemText.trim() && onItemAdd) {
      onItemAdd(newItemText.trim());
      setNewItemText('');
    }
  };

  const completedCount = items.filter(item => item.completed).length;
  const totalCount = items.length;
  const progress = totalCount > 0 ? (completedCount / totalCount) * 100 : 0;

  return (
    <div className="space-y-4">
      {/* Progress Bar */}
      {totalCount > 0 && (
        <div className="space-y-2">
          <div className="flex justify-between items-center text-sm">
            <span className="text-gray-400">Progress</span>
            <span className="text-cyan-400 font-mono">
              {completedCount} / {totalCount}
            </span>
          </div>
          <div className="w-full bg-slate-900 rounded-full h-2 overflow-hidden border border-slate-800">
            <div
              className="h-full bg-gradient-to-r from-cyan-500 to-purple-500 transition-all duration-300"
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>
      )}

      {/* Checklist Items */}
      <div className="space-y-2">
        {items.map((item) => (
          <div
            key={item.id}
            className="group flex items-center gap-3 p-2.5 rounded-lg bg-slate-900/50 border border-slate-800/50 hover:border-cyan-500/30 hover:bg-slate-900 transition-all"
          >
            {/* Checkbox */}
            <button
              onClick={() => onItemToggle(item.id, !item.completed)}
              disabled={readOnly}
              className={`flex-shrink-0 w-5 h-5 rounded border-2 transition-all flex items-center justify-center ${
                item.completed
                  ? 'bg-cyan-500 border-cyan-500'
                  : 'border-slate-600 hover:border-cyan-400'
              } ${readOnly ? 'cursor-default' : 'cursor-pointer'}`}
            >
              {item.completed && <Check size={14} className="text-slate-900" />}
            </button>

            {/* Text */}
            {editingId === item.id ? (
              <input
                autoFocus
                type="text"
                value={editText}
                onChange={(e) => setEditText(e.target.value)}
                className="flex-1 bg-slate-800 border border-cyan-500/50 rounded px-2 py-1 text-sm text-gray-300 focus:outline-none"
              />
            ) : (
              <span
                className={`flex-1 text-sm ${
                  item.completed
                    ? 'text-gray-500 line-through'
                    : 'text-gray-300'
                }`}
              >
                {item.text}
              </span>
            )}

            {/* Actions */}
            <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
              {editingId === item.id ? (
                <>
                  <button
                    onClick={() => handleSave(item.id)}
                    className="p-1 text-emerald-400 hover:bg-emerald-900/20 rounded transition-colors"
                    title="Save"
                  >
                    <Save size={14} />
                  </button>
                  <button
                    onClick={() => setEditingId(null)}
                    className="p-1 text-gray-500 hover:bg-slate-800 rounded transition-colors"
                    title="Cancel"
                  >
                    <X size={14} />
                  </button>
                </>
              ) : (
                <>
                  {!readOnly && (
                    <>
                      <button
                        onClick={() => handleEdit(item)}
                        className="p-1 text-gray-500 hover:text-cyan-400 hover:bg-slate-800 rounded transition-colors"
                        title="Edit"
                      >
                        <Edit2 size={14} />
                      </button>
                      <button
                        onClick={() => onItemDelete?.(item.id)}
                        className="p-1 text-gray-500 hover:text-red-400 hover:bg-slate-800 rounded transition-colors"
                        title="Delete"
                      >
                        <Trash2 size={14} />
                      </button>
                    </>
                  )}
                </>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* Add New Item */}
      {!readOnly && (
        <div className="flex gap-2 pt-2">
          <input
            type="text"
            value={newItemText}
            onChange={(e) => setNewItemText(e.target.value)}
            onKeyPress={(e) => e.key === 'Enter' && handleAddItem()}
            placeholder="Add new step..."
            className="flex-1 bg-slate-900 border border-slate-800 rounded px-3 py-2 text-sm text-gray-300 placeholder-gray-600 focus:outline-none focus:border-cyan-500/50"
          />
          <button
            onClick={handleAddItem}
            className="flex items-center gap-2 px-3 py-2 bg-cyan-600 hover:bg-cyan-700 text-white text-sm rounded transition-colors"
          >
            <Plus size={14} />
            Add
          </button>
        </div>
      )}

      {items.length === 0 && (
        <div className="text-center py-6 text-gray-500 text-sm">
          No checklist items. {!readOnly && 'Add items to get started.'}
        </div>
      )}
    </div>
  );
}
