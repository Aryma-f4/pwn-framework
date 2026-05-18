'use client';

import React, { useState, useRef, useEffect, ReactNode } from 'react';
import { GripVertical } from 'lucide-react';

interface ResizablePanelProps {
  children: ReactNode;
  initialWidth?: number;
  minWidth?: number;
  maxWidth?: number;
  onResize?: (width: number) => void;
  position?: 'left' | 'right';
}

export function ResizablePanel({
  children,
  initialWidth = 400,
  minWidth = 250,
  maxWidth = 800,
  onResize,
  position = 'right',
}: ResizablePanelProps) {
  const [width, setWidth] = useState(initialWidth);
  const [isResizing, setIsResizing] = useState(false);
  const panelRef = useRef<HTMLDivElement>(null);
  const startXRef = useRef(0);
  const startWidthRef = useRef(0);

  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      if (!isResizing) return;

      const deltaX = e.clientX - startXRef.current;
      let newWidth = startWidthRef.current;

      if (position === 'right') {
        newWidth = startWidthRef.current - deltaX;
      } else {
        newWidth = startWidthRef.current + deltaX;
      }

      newWidth = Math.max(minWidth, Math.min(maxWidth, newWidth));
      setWidth(newWidth);
      onResize?.(newWidth);
    };

    const handleMouseUp = () => {
      setIsResizing(false);
    };

    if (isResizing) {
      document.addEventListener('mousemove', handleMouseMove);
      document.addEventListener('mouseup', handleMouseUp);
      document.body.style.cursor = 'col-resize';
      document.body.style.userSelect = 'none';

      return () => {
        document.removeEventListener('mousemove', handleMouseMove);
        document.removeEventListener('mouseup', handleMouseUp);
        document.body.style.cursor = 'auto';
        document.body.style.userSelect = 'auto';
      };
    }
  }, [isResizing, position, minWidth, maxWidth, onResize]);

  const handleMouseDown = (e: React.MouseEvent) => {
    setIsResizing(true);
    startXRef.current = e.clientX;
    startWidthRef.current = width;
  };

  return (
    <div
      ref={panelRef}
      style={{ width: `${width}px` }}
      className="flex flex-col overflow-hidden border-l border-blue-500/20 bg-gradient-to-b from-slate-900 to-slate-950 transition-shadow duration-300 hover:border-blue-500/40 relative group"
    >
      {/* Resizable Divider */}
      <div
        onMouseDown={handleMouseDown}
        className={`${
          position === 'right' ? '-left-1' : '-right-1'
        } absolute top-0 bottom-0 w-1 cursor-col-resize opacity-0 group-hover:opacity-100 transition-opacity duration-200 z-50`}
      >
        <div className="h-full w-full bg-blue-500/50 hover:bg-blue-400 transition-colors duration-200 flex items-center justify-center">
          <GripVertical className="w-3 h-3 text-blue-300 opacity-0 group-hover:opacity-100 transition-opacity" />
        </div>
      </div>

      {/* Panel Content */}
      <div className="flex-1 overflow-auto">
        {children}
      </div>
    </div>
  );
}
