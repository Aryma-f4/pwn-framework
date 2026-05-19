// Interactive UI utilities for enhanced dashboard experience
export interface TooltipConfig {
  title: string;
  description: string;
  difficulty?: 'Easy' | 'Medium' | 'Hard' | 'Expert';
  tactics?: string[];
  relatedTechniques?: string[];
}

export interface KeyboardShortcut {
  key: string;
  description: string;
  action: string;
}

export const KEYBOARD_SHORTCUTS: KeyboardShortcut[] = [
  { key: '/', description: 'Focus search', action: 'search' },
  { key: 'Escape', description: 'Clear search & filters', action: 'clear' },
  { key: 'Enter', description: 'Confirm selection', action: 'confirm' },
  { key: 'ArrowUp', description: 'Select previous technique', action: 'prev' },
  { key: 'ArrowDown', description: 'Select next technique', action: 'next' },
  { key: '?', description: 'Show keyboard help', action: 'help' },
  { key: 'ctrl+f', description: 'Advanced filter modal', action: 'filter' },
  { key: 'ctrl+p', description: 'Pin/unpin technique', action: 'pin' },
];

export const TECHNIQUE_TOOLTIPS: Record<string, TooltipConfig> = {
  'fastbin-dup': {
    title: 'Fastbin Duplication',
    description: 'Exploit double-free to allocate the same chunk twice. Classic heap exploitation.',
    difficulty: 'Easy',
    tactics: ['Chunk Corruption', 'Memory Disclosure', 'Arbitrary Write'],
    relatedTechniques: ['fastbin-dup-into-stack', 'tcache-poisoning']
  },
  'fastbin-dup-into-stack': {
    title: 'Fastbin Dup into Stack',
    description: 'Double-free heap chunk to allocate memory in stack area. Enables stack manipulation.',
    difficulty: 'Medium',
    tactics: ['Stack Corruption', 'ROP Setup'],
    relatedTechniques: ['fastbin-dup', 'house-of-spirit']
  },
  'tcache-poisoning': {
    title: 'Tcache Poisoning',
    description: 'Corrupt tcache linked list to allocate arbitrary memory. Modern glibc exploitation.',
    difficulty: 'Medium',
    tactics: ['Use-After-Free', 'Arbitrary Allocation'],
    relatedTechniques: ['tcache-dup', 'house-of-einherjar']
  },
  'tcache-dup': {
    title: 'Tcache Duplicate Free',
    description: 'Free same chunk twice to tcache without checks. Glibc 2.26-2.29 vulnerability.',
    difficulty: 'Easy',
    tactics: ['Double-Free', 'Arbitrary Allocation'],
    relatedTechniques: ['tcache-poisoning', 'fastbin-dup']
  },
  'house-of-spirit': {
    title: 'House of Spirit',
    description: 'Create fake chunk on stack and free it to get stack allocation.',
    difficulty: 'Medium',
    tactics: ['Stack Overflow', 'Chunk Forgery'],
    relatedTechniques: ['house-of-lore', 'house-of-force']
  },
  'house-of-force': {
    title: 'House of Force',
    description: 'Corrupt top chunk size to allocate at arbitrary address. Powerful but complex.',
    difficulty: 'Hard',
    tactics: ['Top Chunk Corruption', 'Arbitrary Allocation'],
    relatedTechniques: ['house-of-spirit', 'house-of-einherjar']
  },
  'house-of-lore': {
    title: 'House of Lore',
    description: 'Corrupt small-bin backward pointer to allocate at arbitrary address.',
    difficulty: 'Hard',
    tactics: ['Bin Corruption', 'Unlink Exploitation'],
    relatedTechniques: ['house-of-einherjar', 'unsorted-bin-attack']
  },
  'unsorted-bin-attack': {
    title: 'Unsorted Bin Attack',
    description: 'Write large value to arbitrary address by corrupting unsorted bin.',
    difficulty: 'Medium',
    tactics: ['Bin Corruption', 'Arbitrary Write'],
    relatedTechniques: ['house-of-einherjar', 'house-of-lore']
  },
  'house-of-einherjar': {
    title: 'House of Einherjar',
    description: 'Forge chunk in freed memory via corrupted prev_size. Most complex technique.',
    difficulty: 'Expert',
    tactics: ['Coalescing Exploitation', 'Precision Offsets'],
    relatedTechniques: ['house-of-force', 'house-of-lore']
  },
  'large-bin-attack': {
    title: 'Large Bin Attack',
    description: 'Corrupt large-bin to write large values to multiple arbitrary addresses.',
    difficulty: 'Expert',
    tactics: ['Bin Corruption', 'Multi-target Write'],
    relatedTechniques: ['house-of-einherjar', 'unsorted-bin-attack']
  },

  // New tooltips for expanded KB
  'srop': {
    title: 'Sigreturn Oriented Programming (SROP)',
    description: 'Fakes a signal frame to set all registers at once. One-shot ROP for large overflows.',
    difficulty: 'Medium',
    tactics: ['Signal Frame Forgery', 'All-Register Control', 'ORW Chaining'],
    relatedTechniques: ['ret2vdso', 'rop_chain']
  },
  'stack-pivot': {
    title: 'Stack Pivot',
    description: 'Relocates RSP to attacker-controlled memory via leave;ret or xchg gadgets.',
    difficulty: 'Medium',
    tactics: ['RSP Redirection', 'Fake Frame Setup', 'Small Overflow Mitigation'],
    relatedTechniques: ['rop_chain', 'off-by-one']
  },
  'brop': {
    title: 'Blind ROP (BROP)',
    description: 'Brute-forces ROP gadgets on remote forking servers without binary access.',
    difficulty: 'Expert',
    tactics: ['Gadget Brute-Force', 'Binary Dumping', 'No-Binary Exploitation'],
    relatedTechniques: ['rop_chain']
  },
  'jop': {
    title: 'Jump Oriented Programming (JOP)',
    description: 'Uses indirect jumps/calls instead of returns. Bypasses shadow stacks (CET).',
    difficulty: 'Expert',
    tactics: ['Dispatcher Gadgets', 'Shadow Stack Bypass', 'Indirect Jump Chains'],
    relatedTechniques: ['rop_chain', 'brop']
  },
  'ret2vdso': {
    title: 'ret2vdso',
    description: 'Calls kernel vDSO syscalls (gettimeofday/rt_sigreturn) directly in user-space.',
    difficulty: 'Hard',
    tactics: ['vDSO Leak', 'Kernel Syscall Trampoline', 'ret2syscall'],
    relatedTechniques: ['srop', 'rop_chain']
  },
  'integer-overflow': {
    title: 'Integer Overflow Exploitation',
    description: 'Integer arithmetic wraps around, causing undersized allocations or bypassed size checks.',
    difficulty: 'Medium',
    tactics: ['Size Calculation Abuse', 'Signed/Unsigned Confusion', 'malloc Wraparound'],
    relatedTechniques: ['off-by-one', 'heap_exploit']
  },
  'integer-underflow': {
    title: 'Integer Underflow Exploitation',
    description: 'Subtraction wraps to huge unsigned value, bypassing bounds checks.',
    difficulty: 'Medium',
    tactics: ['Size-1 Wraparound', 'Negative Input Abuse', 'Oversized Copy'],
    relatedTechniques: ['integer-overflow', 'buffer_overflow']
  },
  'sign-extension': {
    title: 'Sign Extension Vulnerability',
    description: 'Small negative signed type cast to wider unsigned type becomes 0xFFFFFFFF.',
    difficulty: 'Medium',
    tactics: ['Type Mismatch Abuse', 'Implicit Cast Exploitation'],
    relatedTechniques: ['integer-overflow']
  },
  'off-by-one': {
    title: 'Off-by-One Error Exploitation',
    description: 'Single overflow byte corrupts saved RBP LSB or heap chunk PREV_INUSE bit.',
    difficulty: 'Hard',
    tactics: ['NULL Byte Poisoning', 'RBP LSB Overwrite', 'Heap Coalescing'],
    relatedTechniques: ['stack-pivot', 'house-of-einherjar']
  },
  'uaf': {
    title: 'Use-After-Free (UAF)',
    description: 'Dangling pointer after free() is reused. Reallocate to hijack object.',
    difficulty: 'Medium',
    tactics: ['Dangling Pointer', 'Object Reallocation', 'vtable/Function Pointer Hijack'],
    relatedTechniques: ['double-free', 'tcache-poisoning']
  },
  'house-of-botcake': {
    title: 'House of Botcake',
    description: 'Bypasses tcache double-free checks via chunk consolidation. Glibc 2.29+.',
    difficulty: 'Hard',
    tactics: ['Tcache Evasion', 'Chunk Consolidation', 'Overlapping Allocations'],
    relatedTechniques: ['tcache-poisoning', 'tcache-dup']
  },
  'house-of-apple': {
    title: 'House of Apple (1 & 2)',
    description: 'Hijacks _IO_FILE chains via _IO_wstr_jumps in glibc 2.34+ (post-hook era).',
    difficulty: 'Expert',
    tactics: ['FSOP', 'Wide Data Forgery', 'Vtable Redirection'],
    relatedTechniques: ['fsop_exploit', 'house-of-orange']
  },
  'house-of-orange': {
    title: 'House of Orange',
    description: 'Corrupts top chunk to trigger sysmalloc → FSOP during abort(). No free() needed.',
    difficulty: 'Expert',
    tactics: ['Top Chunk + FSOP', 'abort() Hijack', 'No-Free Exploit'],
    relatedTechniques: ['house-of-force', 'fsop_exploit']
  },
  'tcache-stashing': {
    title: 'Tcache Stashing Unlink',
    description: 'calloc() bypasses tcache, stashes smallbin chunks → corrupted bk → arbitrary write.',
    difficulty: 'Hard',
    tactics: ['calloc Bypass', 'Smallbin Corruption', 'Stashing Mechanism'],
    relatedTechniques: ['tcache-poisoning', 'unsorted-bin-attack']
  },
  'ebpf-exploit': {
    title: 'eBPF Verifier Bypass',
    description: 'Tricks the kernel eBPF verifier into loading a malicious BPF program for kernel R/W.',
    difficulty: 'Expert',
    tactics: ['Verifier Bounds Bypass', 'BPF Bytecode Crafting', 'Kernel R/W'],
    relatedTechniques: ['kernel-rce', 'privilege-escalation']
  },
  'kernel-priv-esc': {
    title: 'Kernel Privilege Escalation',
    description: 'Elevates from user to root via kernel cred overwrite or modprobe_path hijack.',
    difficulty: 'Expert',
    tactics: ['commit_creds', 'modprobe_path', 'Kernel ROP', 'ret2usr'],
    relatedTechniques: ['ebpf-exploit', 'ret2usr']
  },
  'ret2usr': {
    title: 'ret2usr',
    description: 'Redirects kernel execution to user-space shellcode. Requires SMEP disabled.',
    difficulty: 'Hard',
    tactics: ['Kernel → Userspace Pivot', 'SMEP Bypass', 'Direct Code Execution'],
    relatedTechniques: ['kernel-priv-esc', 'rop_chain']
  },
  'modprobe-path': {
    title: 'modprobe_path Overwrite',
    description: 'Overwrites kernel modprobe_path string -> kernel runs attacker script as root.',
    difficulty: 'Medium',
    tactics: ['Arbitrary Kernel Write', 'Root Script Execution', 'SUID Binary Plant'],
    relatedTechniques: ['kernel-priv-esc']
  },

  // how2heap new tooltips
  'unsafe-unlink': {
    title: 'Unsafe Unlink',
    description: 'Corrupts fd/bk of unsorted bin chunk to write heap pointer to arbitrary address via allocator unlink.',
    difficulty: 'Medium',
    tactics: ['Bin Corruption', 'Arbitrary Write', 'Unsorted Bin'],
    relatedTechniques: ['overlapping-chunks', 'unsorted-bin-attack']
  },
  'overlapping-chunks': {
    title: 'Overlapping Chunks',
    description: 'Corrupts chunk size field to cause subsequent malloc to return overlapping memory regions.',
    difficulty: 'Hard',
    tactics: ['Size Corruption', 'Overlapping Allocation', 'Arbitrary R/W'],
    relatedTechniques: ['unsafe-unlink', 'house-of-einherjar']
  },
  'unsorted-bin-into-stack': {
    title: 'Unsorted Bin into Stack',
    description: 'Corrupts unsorted bin bk pointer to make malloc return pointer at attacker-controlled address.',
    difficulty: 'Hard',
    tactics: ['Bin Corruption', 'Arbitrary Allocation', 'bk Pointer Abuse'],
    relatedTechniques: ['unsafe-unlink', 'unsorted-bin-attack']
  },
  'house-of-water': {
    title: 'House of Water',
    description: 'Leakless tcache metadata control via UAF to insert arbitrary addresses into tcache.',
    difficulty: 'Expert',
    tactics: ['Leakless Exploit', 'Tcache Metadata', 'Arbitrary Allocation'],
    relatedTechniques: ['tcache-poisoning', 'tcache-metadata-poisoning']
  },
  'house-of-tangerine': {
    title: 'House of Tangerine',
    description: 'Modern top chunk + tcache technique for arbitrary allocation without free() call.',
    difficulty: 'Expert',
    tactics: ['Top Chunk Corruption', 'Sysmalloc', 'Tcache Poisoning'],
    relatedTechniques: ['house-of-force', 'house-of-orange']
  },
  'tcache-house-of-spirit': {
    title: 'Tcache House of Spirit',
    description: 'Frees fake chunk on stack/BSS to get malloc to return arbitrary pointer via tcache.',
    difficulty: 'Medium',
    tactics: ['Fake Chunk', 'Stack Allocation', 'Tcache Freelist'],
    relatedTechniques: ['house-of-spirit', 'tcache-poisoning']
  },
  'fastbin-reverse-into-tcache': {
    title: 'Fastbin Reverse into Tcache',
    description: 'Corrupts fastbin chunk to write heap pointer to arbitrary address during tcache population.',
    difficulty: 'Hard',
    tactics: ['Fastbin Corruption', 'Consolidation', 'Arbitrary Write'],
    relatedTechniques: ['fastbin-dup', 'tcache-poisoning']
  },
  'house-of-mind-fastbin': {
    title: 'House of Mind (Fastbin)',
    description: 'Single byte arena index corruption to redirect free() to fake arena with controlled fastbins.',
    difficulty: 'Expert',
    tactics: ['Arena Corruption', 'Fake Arena', 'Fastbin Hijack'],
    relatedTechniques: ['house-of-gods', 'fastbin-dup']
  },
  'house-of-storm': {
    title: 'House of Storm',
    description: 'UAF on both large bin and unsorted bin to return arbitrary chunk from malloc.',
    difficulty: 'Expert',
    tactics: ['Dual Bin Corruption', 'Large Bin', 'Unsorted Bin'],
    relatedTechniques: ['large-bin-attack', 'unsorted-bin-attack']
  },
  'house-of-gods': {
    title: 'House of Gods',
    description: 'Hijacks thread arena within 8 allocations via fake arena structure.',
    difficulty: 'Expert',
    tactics: ['Arena Hijack', 'TLS Corruption', 'Thread Isolation'],
    relatedTechniques: ['house-of-mind-fastbin', 'house-of-water']
  },
  'decrypt-safe-linking': {
    title: 'Decrypt Safe Linking',
    description: 'Reverses glibc 2.32+ safe linking XOR to recover actual fd pointers for exploitation.',
    difficulty: 'Medium',
    tactics: ['XOR Decryption', 'Pointer Recovery', 'Safe Linking Bypass'],
    relatedTechniques: ['tcache-poisoning', 'safe-link-double-protect']
  },
  'tcache-metadata-poisoning': {
    title: 'Tcache Metadata Poisoning',
    description: 'Directly corrupts tcache_perthread_struct counts/entries for arbitrary allocation.',
    difficulty: 'Hard',
    tactics: ['Metadata Corruption', 'Direct Struct Write', 'No Chunk Corruption'],
    relatedTechniques: ['house-of-water', 'tcache-poisoning']
  },
  'house-of-io': {
    title: 'House of IO',
    description: 'UAF on tcache chunk to corrupt tcache metadata and achieve arbitrary pointer return.',
    difficulty: 'Hard',
    tactics: ['UAF', 'Tcache Metadata', 'Arbitrary Allocation'],
    relatedTechniques: ['tcache-metadata-poisoning', 'house-of-water']
  },
  'tcache-relative-write': {
    title: 'Tcache Relative Write',
    description: 'OOB write into tcache counts array to manipulate allocation behavior.',
    difficulty: 'Hard',
    tactics: ['OOB Write', 'Count Manipulation', 'Tcache Control'],
    relatedTechniques: ['tcache-metadata-poisoning', 'tcache-metadata-hijacking']
  },
  'tcache-metadata-hijacking': {
    title: 'Tcache Metadata Hijacking',
    description: 'Latest technique (glibc 2.42+) exploiting tcache metadata for arbitrary allocation.',
    difficulty: 'Expert',
    tactics: ['Modern Exploit', 'Metadata Overflow', 'Tcache Control'],
    relatedTechniques: ['tcache-relative-write', 'tcache-metadata-poisoning']
  },
  'fastbin-dup-consolidate': {
    title: 'Fastbin Dup Consolidate',
    description: 'Double-free + consolidation to put chunk in both fastbin and unsorted bin for overlapping chunks.',
    difficulty: 'Hard',
    tactics: ['Double Free', 'Consolidation', 'Overlapping Chunks'],
    relatedTechniques: ['fastbin-dup', 'overlapping-chunks']
  },
  'mmap-overlapping-chunks': {
    title: 'Mmap Overlapping Chunks',
    description: 'Corrupts mmap chunk size to cause overlapping allocations with mmap regions.',
    difficulty: 'Hard',
    tactics: ['Mmap Corruption', 'Size Overflow', 'Overlapping Allocation'],
    relatedTechniques: ['overlapping-chunks', 'house-of-force']
  },
  'sysmalloc-int-free': {
    title: 'Sysmalloc Int Free',
    description: 'Triggers sysmalloc to free top chunk into bin for standard bin exploitation.',
    difficulty: 'Medium',
    tactics: ['Sysmalloc Trigger', 'Top Chunk Free', 'Bin Placement'],
    relatedTechniques: ['house-of-force', 'house-of-tangerine']
  },
  'safe-link-double-protect': {
    title: 'Safe Link Double Protect',
    description: 'Leakless bypass for PROTECT_PTR by writing fd twice with different XOR values.',
    difficulty: 'Expert',
    tactics: ['Double XOR', 'PROTECT_PTR Bypass', 'Leakless Exploit'],
    relatedTechniques: ['decrypt-safe-linking', 'tcache-poisoning']
  },
};

export const KEYBOARD_HELP = `
┌─────────────────────────────────────────────────┐
│         KEYBOARD SHORTCUTS & CONTROLS           │
├─────────────────────────────────────────────────┤
│ /            │ Focus search bar                  │
│ Escape       │ Clear all filters & search        │
│ Enter        │ Confirm node selection             │
│ ↑/↓          │ Navigate between techniques       │
│ Ctrl+F       │ Open advanced filter modal         │
│ Ctrl+P       │ Pin/unpin current technique       │
│ ?            │ Show this help dialog             │
│ Double-Click │ Expand/collapse node children     │
│ Hover        │ View technique tooltips           │
└─────────────────────────────────────────────────┘
`;

export const animationClasses = {
  nodeHover: 'node-hover-glow',
  nodeSelect: 'node-select-pulse',
  tooltipFadeIn: 'tooltip-fade-in',
  transitionSmooth: 'transition-all duration-300 ease-in-out'
};

export function createTooltipContent(technique: TooltipConfig): string {
  return `
    <div class="tooltip-header">${technique.title}</div>
    <p class="tooltip-desc">${technique.description}</p>
    ${technique.difficulty ? `<div class="tooltip-difficulty">${technique.difficulty}</div>` : ''}
    ${technique.tactics ? `<div class="tooltip-tactics">${technique.tactics.join(' • ')}</div>` : ''}
  `;
}
