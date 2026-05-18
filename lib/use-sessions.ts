import { useState, useEffect } from 'react';

export interface ChecklistItem {
  id: string;
  text: string;
  completed: boolean;
}

export interface Session {
  id: string;
  name: string;
  createdAt: number;
  updatedAt: number;
  checklist: ChecklistItem[];
  technique: string;
}

const STORAGE_KEY = 'pwn_sessions';

export function useSessions() {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [activeSessionId, setActiveSessionId] = useState<string | null>(null);
  const [isLoaded, setIsLoaded] = useState(false);

  // Load sessions from localStorage on mount
  useEffect(() => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        const parsed = JSON.parse(stored);
        setSessions(Array.isArray(parsed) ? parsed : []);
        
        // Set first session as active if available
        if (Array.isArray(parsed) && parsed.length > 0) {
          setActiveSessionId(parsed[0].id);
        }
      }
    } catch (error) {
      console.error('[v0] Failed to load sessions from localStorage:', error);
    }
    setIsLoaded(true);
  }, []);

  // Save sessions to localStorage whenever they change
  useEffect(() => {
    if (isLoaded) {
      try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(sessions));
      } catch (error) {
        console.error('[v0] Failed to save sessions to localStorage:', error);
      }
    }
  }, [sessions, isLoaded]);

  const createSession = (technique: string, initialChecklist: ChecklistItem[] = []): string => {
    const id = `session_${Date.now()}`;
    const newSession: Session = {
      id,
      name: `${technique} - ${new Date().toLocaleDateString()}`,
      createdAt: Date.now(),
      updatedAt: Date.now(),
      checklist: initialChecklist,
      technique,
    };
    setSessions([...sessions, newSession]);
    setActiveSessionId(id);
    return id;
  };

  const deleteSession = (id: string) => {
    const filtered = sessions.filter(s => s.id !== id);
    setSessions(filtered);
    if (activeSessionId === id) {
      setActiveSessionId(filtered.length > 0 ? filtered[0].id : null);
    }
  };

  const renameSession = (id: string, newName: string) => {
    setSessions(sessions.map(s =>
      s.id === id ? { ...s, name: newName, updatedAt: Date.now() } : s
    ));
  };

  const updateChecklistItem = (sessionId: string, itemId: string, completed: boolean) => {
    setSessions(sessions.map(s =>
      s.id === sessionId
        ? {
            ...s,
            updatedAt: Date.now(),
            checklist: s.checklist.map(item =>
              item.id === itemId ? { ...item, completed } : item
            ),
          }
        : s
    ));
  };

  const setChecklist = (sessionId: string, checklist: ChecklistItem[]) => {
    setSessions(sessions.map(s =>
      s.id === sessionId
        ? { ...s, updatedAt: Date.now(), checklist }
        : s
    ));
  };

  const getActiveSession = () => {
    return activeSessionId ? sessions.find(s => s.id === activeSessionId) : null;
  };

  const clearAllSessions = () => {
    setSessions([]);
    setActiveSessionId(null);
  };

  return {
    sessions,
    activeSessionId,
    setActiveSessionId,
    createSession,
    deleteSession,
    renameSession,
    updateChecklistItem,
    setChecklist,
    getActiveSession,
    clearAllSessions,
    isLoaded,
  };
}
