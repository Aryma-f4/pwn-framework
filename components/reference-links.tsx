'use client';

import { ExternalLink, Book, Github } from 'lucide-react';

interface ReferenceLinksProps {
  techniqueName: string;
  how2heapLink?: string;
  dhavalkapilChapter?: string;
  ctfChallenges?: Array<{ name: string; year: string; link: string }>;
}

export function ReferenceLinks({
  techniqueName,
  how2heapLink,
  dhavalkapilChapter,
  ctfChallenges,
}: ReferenceLinksProps) {
  return (
    <div className="space-y-3">
      {/* how2heap Link */}
      {how2heapLink && (
        <a
          href={how2heapLink}
          target="_blank"
          rel="noopener noreferrer"
          className="block bg-slate-900/50 border border-slate-700 rounded p-3 hover:border-blue-500/50 transition-all group"
        >
          <div className="flex items-center gap-2 mb-1">
            <Github size={14} className="text-blue-400" />
            <span className="text-sm font-mono text-blue-300">shellphish/how2heap</span>
            <ExternalLink size={12} className="opacity-0 group-hover:opacity-100 transition-opacity" />
          </div>
          <p className="text-xs text-gray-400">View implementation and exploit code</p>
        </a>
      )}

      {/* Dhavalkapil's Heap Exploitation */}
      {dhavalkapilChapter && (
        <a
          href={dhavalkapilChapter}
          target="_blank"
          rel="noopener noreferrer"
          className="block bg-slate-900/50 border border-slate-700 rounded p-3 hover:border-purple-500/50 transition-all group"
        >
          <div className="flex items-center gap-2 mb-1">
            <Book size={14} className="text-purple-400" />
            <span className="text-sm font-mono text-purple-300">heap-exploitation.dhavalkapil.com</span>
            <ExternalLink size={12} className="opacity-0 group-hover:opacity-100 transition-opacity" />
          </div>
          <p className="text-xs text-gray-400">Comprehensive heap exploitation guide</p>
        </a>
      )}

      {/* CTF Challenges */}
      {ctfChallenges && ctfChallenges.length > 0 && (
        <div>
          <div className="text-xs font-mono text-cyan-400 mb-2 uppercase tracking-wider">
            CTF References
          </div>
          <div className="space-y-1">
            {ctfChallenges.map((challenge, idx) => (
              <a
                key={idx}
                href={challenge.link}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-2 text-xs text-gray-400 hover:text-cyan-300 transition-colors bg-slate-800/20 p-2 rounded border border-slate-700/50 hover:border-cyan-500/50"
              >
                <span className="text-gray-600">{challenge.year}</span>
                <span>{challenge.name}</span>
                <ExternalLink size={10} className="ml-auto" />
              </a>
            ))}
          </div>
        </div>
      )}

      {/* Additional Resources */}
      <div className="bg-slate-800/30 border border-slate-700/50 rounded p-2 text-xs text-gray-400">
        <p className="mb-1 font-mono text-cyan-300">Quick Tips:</p>
        <ul className="space-y-0.5 text-xs text-gray-500">
          <li>• Use gdb/pwndbg for debugging and leak confirmation</li>
          <li>• Check libc version with <code className="bg-black/30 px-1 rounded text-gray-300">ldd ./binary</code></li>
          <li>• Test with checksec to identify protections</li>
          <li>• Use one_gadget for quick RCE when applicable</li>
        </ul>
      </div>
    </div>
  );
}
