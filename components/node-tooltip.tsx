'use client';

import { useEffect, useState } from 'react';
import { TECHNIQUE_TOOLTIPS } from '@/lib/interactive-utils';

interface NodeTooltipProps {
  techniqueId: string;
  x: number;
  y: number;
  visible: boolean;
}

export function NodeTooltip({ techniqueId, x, y, visible }: NodeTooltipProps) {
  const tooltip = TECHNIQUE_TOOLTIPS[techniqueId];

  if (!visible || !tooltip) return null;

  // Adjust position to stay within viewport
  const adjustedX = Math.min(x, window.innerWidth - 300);
  const adjustedY = Math.max(y, 100);

  return (
    <div
      className="pwn-tooltip tooltip-fade-in"
      style={{
        left: `${adjustedX}px`,
        top: `${adjustedY - 40}px`,
        maxWidth: '280px'
      }}
    >
      <div className="tooltip-header">{tooltip.title}</div>
      <p className="tooltip-desc">{tooltip.description}</p>
      {tooltip.difficulty && (
        <div className="tooltip-difficulty">
          Difficulty: {tooltip.difficulty}
        </div>
      )}
      {tooltip.tactics && (
        <div className="tooltip-tactics">
          {tooltip.tactics.join(' • ')}
        </div>
      )}
    </div>
  );
}
