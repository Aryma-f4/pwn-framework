'use client';

import { useState } from 'react';
import { ChevronDown, ChevronRight, Copy, Check, Terminal } from 'lucide-react';
import { RECON_STEPS, RECON_CATEGORIES, ReconStep } from '@/lib/pwn-recon-data';

interface ReconWizardProps {
  selectedTags: Set<string>;
  onTagsChange: (tags: Set<string>) => void;
}

export function ReconWizard({ selectedTags, onTagsChange }: ReconWizardProps) {
  const [expandedSteps, setExpandedSteps] = useState<Set<string>>(new Set(['file-type']));
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);

  const toggleStep = (stepId: string) => {
    const next = new Set(expandedSteps);
    if (next.has(stepId)) next.delete(stepId);
    else next.add(stepId);
    setExpandedSteps(next);
  };

  const toggleOption = (option: typeof RECON_STEPS[0]['options'][0], step: ReconStep) => {
    const next = new Set(selectedTags);

    if (option.mutuallyExclusive) {
      // Remove all tags from same group in this step
      step.options
        .filter(o => o.mutuallyExclusive === option.mutuallyExclusive)
        .forEach(o => o.tags.forEach(t => next.delete(t)));
    }

    const isSelected = option.tags.every(t => selectedTags.has(t));
    if (isSelected) {
      option.tags.forEach(t => next.delete(t));
    } else {
      option.tags.forEach(t => next.add(t));
    }

    onTagsChange(next);
  };

  const handleCopy = (cmd: string, stepId: string) => {
    navigator.clipboard.writeText(cmd);
    setCopiedCmd(stepId);
    setTimeout(() => setCopiedCmd(null), 2000);
  };

  const isOptionSelected = (option: typeof RECON_STEPS[0]['options'][0]) => {
    return option.tags.length > 0 && option.tags.every(t => selectedTags.has(t));
  };

  const getStepCompletion = (step: ReconStep) => {
    return step.options.some(o => isOptionSelected(o));
  };

  const categories = Object.entries(RECON_CATEGORIES) as [keyof typeof RECON_CATEGORIES, typeof RECON_CATEGORIES[keyof typeof RECON_CATEGORIES]][];
  const completedSteps = RECON_STEPS.filter(s => getStepCompletion(s)).length;
  const totalSteps = RECON_STEPS.length;
  const progress = totalSteps > 0 ? (completedSteps / totalSteps) * 100 : 0;

  return (
    <div className="recon-wizard space-y-3">
      {/* Progress */}
      <div className="space-y-1.5">
        <div className="flex justify-between text-xs">
          <span className="text-gray-400">Reconnaissance Progress</span>
          <span className="text-cyan-400 font-mono">{completedSteps}/{totalSteps}</span>
        </div>
        <div className="w-full bg-slate-900 rounded-full h-1.5 overflow-hidden border border-slate-800">
          <div
            className="h-full bg-gradient-to-r from-cyan-500 via-purple-500 to-rose-500 transition-all duration-500"
            style={{ width: `${progress}%` }}
          />
        </div>
      </div>

      {/* Steps by category */}
      {categories.map(([catKey, cat]) => {
        const catSteps = RECON_STEPS.filter(s => s.category === catKey);
        if (catSteps.length === 0) return null;

        return (
          <div key={catKey} className="space-y-1.5">
            <div className="flex items-center gap-1.5 text-xs font-mono uppercase tracking-wider" style={{ color: cat.color }}>
              <span>{cat.icon}</span>
              <span>{cat.label}</span>
            </div>

            {catSteps.map(step => {
              const isExpanded = expandedSteps.has(step.id);
              const isComplete = getStepCompletion(step);

              return (
                <div key={step.id} className={`recon-step-card ${isComplete ? 'completed' : ''}`}>
                  {/* Step Header */}
                  <button
                    onClick={() => toggleStep(step.id)}
                    className="w-full flex items-center gap-2 p-2 text-left hover:bg-slate-800/30 rounded transition-colors"
                  >
                    {isExpanded ? (
                      <ChevronDown size={14} className="text-gray-500 flex-shrink-0" />
                    ) : (
                      <ChevronRight size={14} className="text-gray-500 flex-shrink-0" />
                    )}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-semibold text-gray-200 truncate">{step.title}</span>
                        {isComplete && (
                          <span className="flex-shrink-0 w-4 h-4 rounded-full bg-emerald-500/20 border border-emerald-500/50 flex items-center justify-center">
                            <Check size={10} className="text-emerald-400" />
                          </span>
                        )}
                      </div>
                    </div>
                  </button>

                  {/* Step Content */}
                  {isExpanded && (
                    <div className="px-2 pb-2 space-y-2">
                      <p className="text-xs text-gray-500 leading-relaxed">{step.description}</p>

                      {/* Command */}
                      <div className="relative group">
                        <div className="recon-command">
                          <Terminal size={11} className="text-cyan-500/60 flex-shrink-0 mt-0.5" />
                          <pre className="text-xs text-cyan-300/80 font-mono whitespace-pre-wrap break-all flex-1">{step.command}</pre>
                          <button
                            onClick={() => handleCopy(step.command, step.id)}
                            className="flex-shrink-0 p-0.5 text-gray-500 hover:text-cyan-400 transition-colors"
                            title="Copy command"
                          >
                            {copiedCmd === step.id ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
                          </button>
                        </div>
                      </div>

                      {/* Options */}
                      <div className="space-y-1">
                        {step.options.map(option => {
                          const selected = isOptionSelected(option);
                          const isRadio = !!option.mutuallyExclusive;

                          return (
                            <button
                              key={option.id}
                              onClick={() => toggleOption(option, step)}
                              className={`recon-option ${selected ? 'selected' : ''} ${isRadio ? 'radio' : ''}`}
                            >
                              <div className={`recon-option-indicator ${isRadio ? 'radio' : ''} ${selected ? 'selected' : ''}`}>
                                {selected && !isRadio && <Check size={10} />}
                                {selected && isRadio && <div className="w-1.5 h-1.5 rounded-full bg-cyan-400" />}
                              </div>
                              <div className="flex-1 text-left min-w-0">
                                <div className="text-xs font-medium text-gray-200">{option.label}</div>
                                <div className="text-xs text-gray-500 leading-tight">{option.description}</div>
                              </div>
                            </button>
                          );
                        })}
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        );
      })}

      {/* Reset button */}
      {selectedTags.size > 0 && (
        <button
          onClick={() => onTagsChange(new Set())}
          className="w-full text-xs text-gray-500 hover:text-rose-400 transition-colors py-1.5 border border-slate-800 rounded hover:border-rose-500/30"
        >
          Reset All Selections
        </button>
      )}
    </div>
  );
}
