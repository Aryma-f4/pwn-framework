'use client';

import { useState } from 'react';
import { Plus, Trash2, Edit2, Save, X, FolderOpen } from 'lucide-react';
import { Session } from '@/lib/use-sessions';

interface SessionManagerProps {
  sessions: Session[];
  activeSessionId: string | null;
  onCreateSession: (name: string) => void;
  onSelectSession: (id: string) => void;
  onDeleteSession: (id: string) => void;
  onRenameSession: (id: string, newName: string) => void;
  currentTechnique: string;
}

export function SessionManager({
  sessions,
  activeSessionId,
  onCreateSession,
  onSelectSession,
  onDeleteSession,
  onRenameSession,
  currentTechnique,
}: SessionManagerProps) {
  const [showNewSession, setShowNewSession] = useState(false);
  const [newSessionName, setNewSessionName] = useState('');
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editName, setEditName] = useState('');

  const handleCreateSession = () => {
    const name = newSessionName.trim() || `${currentTechnique} - ${new Date().toLocaleDateString()}`;
    onCreateSession(name);
    setNewSessionName('');
    setShowNewSession(false);
  };

  const handleRename = (id: string, currentName: string) => {
    setEditingId(id);
    setEditName(currentName);
  };

  const handleSaveRename = (id: string) => {
    if (editName.trim()) {
      onRenameSession(id, editName.trim());
    }
    setEditingId(null);
    setEditName('');
  };

  return (
    <div className="space-y-3">
      {/* Sessions List */}
      <div className="space-y-2 max-h-48 overflow-y-auto">
        {sessions.map((session) => (
          <div
            key={session.id}
            className={`group flex items-center gap-2 p-2 rounded-lg border transition-all cursor-pointer ${
              activeSessionId === session.id
                ? 'bg-cyan-900/20 border-cyan-500/50'
                : 'bg-slate-900/50 border-slate-800/50 hover:border-slate-700'
            }`}
          >
            {editingId === session.id ? (
              <>
                <input
                  autoFocus
                  type="text"
                  value={editName}
                  onChange={(e) => setEditName(e.target.value)}
                  onClick={(e) => e.stopPropagation()}
                  className="flex-1 bg-slate-800 border border-cyan-500/50 rounded px-2 py-1 text-xs text-gray-300 focus:outline-none"
                />
                <button
                  onClick={() => handleSaveRename(session.id)}
                  className="p-1 text-emerald-400 hover:bg-emerald-900/20 rounded"
                >
                  <Save size={12} />
                </button>
                <button
                  onClick={() => setEditingId(null)}
                  className="p-1 text-gray-500 hover:bg-slate-800 rounded"
                >
                  <X size={12} />
                </button>
              </>
            ) : (
              <>
                <FolderOpen size={14} className="text-cyan-400 flex-shrink-0" />
                <div
                  className="flex-1 min-w-0"
                  onClick={() => onSelectSession(session.id)}
                >
                  <p className="text-xs font-medium text-gray-300 truncate">
                    {session.name}
                  </p>
                  <p className="text-xs text-gray-500">
                    {session.checklist.filter(c => c.completed).length}/{session.checklist.length} completed
                  </p>
                </div>
                <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      handleRename(session.id, session.name);
                    }}
                    className="p-1 text-gray-500 hover:text-cyan-400 hover:bg-slate-800 rounded"
                    title="Rename"
                  >
                    <Edit2 size={12} />
                  </button>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      onDeleteSession(session.id);
                    }}
                    className="p-1 text-gray-500 hover:text-red-400 hover:bg-slate-800 rounded"
                    title="Delete"
                  >
                    <Trash2 size={12} />
                  </button>
                </div>
              </>
            )}
          </div>
        ))}
      </div>

      {/* New Session */}
      {showNewSession ? (
        <div className="flex gap-2">
          <input
            autoFocus
            type="text"
            value={newSessionName}
            onChange={(e) => setNewSessionName(e.target.value)}
            onKeyPress={(e) => e.key === 'Enter' && handleCreateSession()}
            placeholder="Session name..."
            className="flex-1 bg-slate-900 border border-cyan-500/50 rounded px-2 py-1.5 text-xs text-gray-300 focus:outline-none"
          />
          <button
            onClick={handleCreateSession}
            className="px-2 py-1.5 bg-cyan-600 hover:bg-cyan-700 text-white text-xs rounded transition-colors"
          >
            Create
          </button>
          <button
            onClick={() => setShowNewSession(false)}
            className="px-2 py-1.5 bg-slate-800 hover:bg-slate-700 text-gray-300 text-xs rounded transition-colors"
          >
            Cancel
          </button>
        </div>
      ) : (
        <button
          onClick={() => setShowNewSession(true)}
          className="w-full flex items-center justify-center gap-2 px-3 py-2 bg-slate-900 border border-slate-800 hover:border-cyan-500/50 hover:bg-slate-800 rounded-lg text-gray-300 hover:text-cyan-400 text-sm transition-all"
        >
          <Plus size={14} />
          New Session
        </button>
      )}
    </div>
  );
}
