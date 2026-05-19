// Pre-Pwn Reconnaissance Wizard Data

export interface ReconOption {
  id: string;
  label: string;
  description: string;
  tags: string[];
  mutuallyExclusive?: string; // group name for radio-style
}

export interface ReconStep {
  id: string;
  title: string;
  description: string;
  command: string;
  tool: string;
  category: 'basic' | 'protections' | 'analysis' | 'runtime';
  options: ReconOption[];
}

export interface ExploitRecommendation {
  techniqueId: string;
  name: string;
  confidence: 'high' | 'medium' | 'low';
  reason: string;
  requiredLeaks: string[];
  suggestedTools: string[];
}

// ─── RECON STEPS ───

export const RECON_STEPS: ReconStep[] = [
  // ── BASIC INFO ──
  {
    id: 'file-type',
    title: 'File Type & Architecture',
    description: 'Identify binary format, architecture, and linking type.',
    command: 'file ./binary',
    tool: 'file',
    category: 'basic',
    options: [
      { id: 'elf64', label: 'ELF 64-bit', description: 'x86-64 binary', tags: ['elf64'], mutuallyExclusive: 'arch' },
      { id: 'elf32', label: 'ELF 32-bit', description: 'x86 (i386) binary', tags: ['elf32'], mutuallyExclusive: 'arch' },
      { id: 'static', label: 'Statically linked', description: 'No shared libraries', tags: ['static'], mutuallyExclusive: 'link' },
      { id: 'dynamic', label: 'Dynamically linked', description: 'Uses shared libs (libc)', tags: ['dynamic'], mutuallyExclusive: 'link' },
    ],
  },
  {
    id: 'symbols',
    title: 'Symbol Information',
    description: 'Check if the binary has debug symbols or is stripped.',
    command: 'file ./binary && nm ./binary 2>&1 | head -5',
    tool: 'file / nm',
    category: 'basic',
    options: [
      { id: 'not-stripped', label: 'Not stripped', description: 'Symbols available for analysis', tags: ['symbols'], mutuallyExclusive: 'strip' },
      { id: 'stripped', label: 'Stripped', description: 'No symbol info — harder to analyze', tags: ['stripped'], mutuallyExclusive: 'strip' },
    ],
  },
  {
    id: 'libc-version',
    title: 'Libc Version',
    description: 'Identify the libc version linked to the binary.',
    command: 'ldd ./binary | grep libc\nstrings /lib/x86_64-linux-gnu/libc.so.6 | grep "GNU C"',
    tool: 'ldd / strings',
    category: 'basic',
    options: [
      { id: 'glibc-old', label: 'glibc < 2.26', description: 'No tcache, old fastbin checks', tags: ['glibc-old'], mutuallyExclusive: 'glibc' },
      { id: 'glibc-mid', label: 'glibc 2.26–2.31', description: 'Has tcache, no safe-linking', tags: ['glibc-mid'], mutuallyExclusive: 'glibc' },
      { id: 'glibc-new', label: 'glibc 2.32+', description: 'Safe-linking, hardened tcache', tags: ['glibc-new'], mutuallyExclusive: 'glibc' },
      { id: 'glibc-latest', label: 'glibc 2.34+', description: 'No __malloc_hook/__free_hook', tags: ['glibc-latest'], mutuallyExclusive: 'glibc' },
      { id: 'no-libc', label: 'No libc (static)', description: 'Statically linked, no libc', tags: ['no-libc'], mutuallyExclusive: 'glibc' },
    ],
  },

  // ── PROTECTIONS ──
  {
    id: 'canary',
    title: 'Stack Canary',
    description: 'Stack canary protects against stack buffer overflows.',
    command: 'checksec --file=./binary',
    tool: 'checksec',
    category: 'protections',
    options: [
      { id: 'canary-on', label: 'Canary ENABLED', description: 'Stack smashing detected if overwritten', tags: ['canary'], mutuallyExclusive: 'canary' },
      { id: 'canary-off', label: 'Canary DISABLED', description: 'No stack protection — direct overflow', tags: ['no-canary'], mutuallyExclusive: 'canary' },
    ],
  },
  {
    id: 'nx',
    title: 'NX (No-Execute)',
    description: 'NX marks stack/heap as non-executable.',
    command: 'checksec --file=./binary',
    tool: 'checksec',
    category: 'protections',
    options: [
      { id: 'nx-on', label: 'NX ENABLED', description: 'Cannot execute shellcode on stack', tags: ['nx-enabled'], mutuallyExclusive: 'nx' },
      { id: 'nx-off', label: 'NX DISABLED', description: 'Stack is executable — shellcode ok', tags: ['nx-disabled'], mutuallyExclusive: 'nx' },
    ],
  },
  {
    id: 'pie',
    title: 'PIE (Position Independent)',
    description: 'PIE randomizes the binary base address.',
    command: 'checksec --file=./binary',
    tool: 'checksec',
    category: 'protections',
    options: [
      { id: 'pie-on', label: 'PIE ENABLED', description: 'Binary base randomized — need leak', tags: ['pie'], mutuallyExclusive: 'pie' },
      { id: 'pie-off', label: 'PIE DISABLED', description: 'Fixed binary base — addresses known', tags: ['no-pie'], mutuallyExclusive: 'pie' },
    ],
  },
  {
    id: 'relro',
    title: 'RELRO',
    description: 'RELRO protects the GOT from overwrite.',
    command: 'checksec --file=./binary',
    tool: 'checksec',
    category: 'protections',
    options: [
      { id: 'no-relro', label: 'No RELRO', description: 'GOT fully writable', tags: ['no-relro'], mutuallyExclusive: 'relro' },
      { id: 'partial-relro', label: 'Partial RELRO', description: 'GOT writable, .got.plt intact', tags: ['partial-relro'], mutuallyExclusive: 'relro' },
      { id: 'full-relro', label: 'Full RELRO', description: 'GOT read-only — cannot overwrite', tags: ['full-relro'], mutuallyExclusive: 'relro' },
    ],
  },

  // ── VULNERABILITY ANALYSIS ──
  {
    id: 'vuln-type',
    title: 'Vulnerability Type',
    description: 'What type of vulnerability did you identify?',
    command: 'objdump -d ./binary | grep -E "gets|scanf|strcpy|printf|malloc|free"',
    tool: 'objdump / IDA / Ghidra',
    category: 'analysis',
    options: [
      { id: 'stack-bof', label: 'Stack Buffer Overflow', description: 'gets/read/scanf overflow on stack', tags: ['stack-bof'] },
      { id: 'fmt-str', label: 'Format String', description: 'printf(user_input) pattern', tags: ['format-string'] },
      { id: 'heap-overflow', label: 'Heap Overflow', description: 'Overflow in malloc\'d buffer', tags: ['heap-vuln', 'heap-overflow'] },
      { id: 'uaf', label: 'Use-After-Free', description: 'Dangling pointer after free()', tags: ['heap-vuln', 'uaf'] },
      { id: 'double-free', label: 'Double Free', description: 'Same pointer freed twice', tags: ['heap-vuln', 'double-free'] },
      { id: 'integer-overflow', label: 'Integer Overflow', description: 'Size calculation wraparound', tags: ['int-overflow'] },
      { id: 'race-condition', label: 'Race Condition', description: 'TOCTOU or thread race', tags: ['race'] },
    ],
  },
  {
    id: 'input-vector',
    title: 'Input Vector',
    description: 'How does user input reach the vulnerability?',
    command: 'ltrace ./binary 2>&1 | head -20\nstrace ./binary 2>&1 | grep -E "read|recv"',
    tool: 'ltrace / strace',
    category: 'analysis',
    options: [
      { id: 'stdin', label: 'Standard Input (stdin)', description: 'Interactive input via terminal', tags: ['stdin'] },
      { id: 'argv', label: 'Command Arguments (argv)', description: 'Passed via CLI args', tags: ['argv'] },
      { id: 'file-input', label: 'File Input', description: 'Reads from a file', tags: ['file-input'] },
      { id: 'network', label: 'Network (socket)', description: 'Remote service / TCP', tags: ['network'] },
      { id: 'env', label: 'Environment Variable', description: 'Via getenv()', tags: ['env'] },
    ],
  },

  // ── RUNTIME CHECKS ──
  {
    id: 'aslr',
    title: 'ASLR Status',
    description: 'Check if address space layout randomization is active.',
    command: 'cat /proc/sys/kernel/randomize_va_space\n# 0=off, 1=partial, 2=full',
    tool: 'proc filesystem',
    category: 'runtime',
    options: [
      { id: 'aslr-off', label: 'ASLR OFF (0)', description: 'Addresses predictable', tags: ['no-aslr'], mutuallyExclusive: 'aslr' },
      { id: 'aslr-on', label: 'ASLR ON (2)', description: 'Need info leak for addresses', tags: ['aslr'], mutuallyExclusive: 'aslr' },
    ],
  },
  {
    id: 'seccomp',
    title: 'Seccomp / Sandbox',
    description: 'Check if the binary uses seccomp to filter syscalls.',
    command: 'seccomp-tools dump ./binary',
    tool: 'seccomp-tools',
    category: 'runtime',
    options: [
      { id: 'no-seccomp', label: 'No Seccomp', description: 'All syscalls allowed', tags: ['no-seccomp'], mutuallyExclusive: 'seccomp' },
      { id: 'seccomp-execve-blocked', label: 'Seccomp (execve blocked)', description: 'Cannot spawn shell — need ORW', tags: ['seccomp', 'no-execve'], mutuallyExclusive: 'seccomp' },
      { id: 'seccomp-orw-only', label: 'Seccomp (ORW allowed)', description: 'open/read/write permitted', tags: ['seccomp', 'orw-allowed'], mutuallyExclusive: 'seccomp' },
    ],
  },
  {
    id: 'primitives',
    title: 'Available Primitives',
    description: 'What exploit primitives have you confirmed?',
    command: '# Test in GDB with crafted inputs',
    tool: 'GDB / pwndbg',
    category: 'runtime',
    options: [
      { id: 'arb-read', label: 'Arbitrary Read', description: 'Can read from any address', tags: ['arb-read'] },
      { id: 'arb-write', label: 'Arbitrary Write', description: 'Can write to any address', tags: ['arb-write'] },
      { id: 'info-leak', label: 'Info Leak Available', description: 'Can leak stack/heap/libc addresses', tags: ['info-leak'] },
      { id: 'rip-control', label: 'RIP/EIP Control', description: 'Can control instruction pointer', tags: ['rip-control'] },
    ],
  },
];

// ─── EXPLOIT MATCHING RULES ───

interface ExploitRule {
  name: string;
  techniqueId: string;
  requiredTags: string[];    // ALL must match
  boostTags: string[];       // increase confidence if present
  excludeTags: string[];     // exclude if any present
  baseConfidence: 'high' | 'medium' | 'low';
  reason: string;
  requiredLeaks: string[];
  suggestedTools: string[];
}

const EXPLOIT_RULES: ExploitRule[] = [
  // ── STACK-BASED ──
  {
    name: 'ret2shellcode',
    techniqueId: 'buffer_overflow',
    requiredTags: ['stack-bof', 'nx-disabled'],
    boostTags: ['no-canary', 'no-pie', 'no-aslr'],
    excludeTags: ['seccomp'],
    baseConfidence: 'high',
    reason: 'Stack overflow + NX disabled → inject and execute shellcode directly',
    requiredLeaks: [],
    suggestedTools: ['pwntools shellcraft', 'msfvenom', 'pwndbg vmmap'],
  },
  {
    name: 'ret2libc / ROP Chain',
    techniqueId: 'rop_chain',
    requiredTags: ['stack-bof', 'nx-enabled'],
    boostTags: ['no-canary', 'dynamic', 'info-leak'],
    excludeTags: ['static', 'seccomp'],
    baseConfidence: 'high',
    reason: 'Stack overflow + NX enabled → chain libc functions via ROP gadgets',
    requiredLeaks: ['libc base (if ASLR)'],
    suggestedTools: ['ROPgadget', 'ropper', 'one_gadget', 'pwntools ROP'],
  },
  {
    name: 'ret2plt (Info Leak)',
    techniqueId: 'rop_chain',
    requiredTags: ['stack-bof', 'no-pie', 'dynamic'],
    boostTags: ['nx-enabled', 'aslr'],
    excludeTags: ['static'],
    baseConfidence: 'medium',
    reason: 'No PIE + dynamic linking → leak libc via puts@plt(GOT entry)',
    requiredLeaks: [],
    suggestedTools: ['pwntools ELF', 'readelf -r', 'objdump -d'],
  },
  {
    name: 'ret2syscall / SROP',
    techniqueId: 'rop_chain',
    requiredTags: ['stack-bof', 'static'],
    boostTags: ['no-canary', 'rip-control'],
    excludeTags: ['seccomp'],
    baseConfidence: 'medium',
    reason: 'Static binary → no libc, use direct syscall gadgets or sigreturn',
    requiredLeaks: [],
    suggestedTools: ['ROPgadget', 'pwntools SigreturnFrame'],
  },
  {
    name: 'Stack Pivot + ROP',
    techniqueId: 'stack_pivot',
    requiredTags: ['stack-bof', 'rip-control'],
    boostTags: ['nx-enabled'],
    excludeTags: [],
    baseConfidence: 'medium',
    reason: 'Limited overflow space → pivot RSP to controlled buffer for larger ROP chain',
    requiredLeaks: ['writable memory address'],
    suggestedTools: ['ROPgadget (xchg rsp)', 'pwndbg vmmap'],
  },

  // ── FORMAT STRING ──
  {
    name: 'FSB → GOT Overwrite',
    techniqueId: 'format_string',
    requiredTags: ['format-string'],
    boostTags: ['partial-relro', 'no-relro', 'no-pie'],
    excludeTags: ['full-relro'],
    baseConfidence: 'high',
    reason: 'Format string + writable GOT → overwrite function pointer to system()',
    requiredLeaks: ['libc base (if ASLR)'],
    suggestedTools: ['pwntools fmtstr_payload', 'pwndbg got'],
  },
  {
    name: 'FSB → Canary Leak + BOF',
    techniqueId: 'format_string',
    requiredTags: ['format-string', 'canary', 'stack-bof'],
    boostTags: [],
    excludeTags: [],
    baseConfidence: 'high',
    reason: 'FSB leaks canary → bypass stack protection → exploit BOF',
    requiredLeaks: [],
    suggestedTools: ['pwntools', 'pwndbg canary'],
  },
  {
    name: 'FSB → Arbitrary Read/Write',
    techniqueId: 'format_string',
    requiredTags: ['format-string'],
    boostTags: ['info-leak', 'arb-write'],
    excludeTags: [],
    baseConfidence: 'medium',
    reason: 'Format string → leak addresses with %p, write with %n',
    requiredLeaks: ['format string offset'],
    suggestedTools: ['pwntools fmtstr_payload', 'manual %N$p probing'],
  },

  // ── HEAP ──
  {
    name: 'Tcache Poisoning',
    techniqueId: 'heap_exploit',
    requiredTags: ['heap-vuln', 'glibc-mid'],
    boostTags: ['uaf', 'heap-overflow'],
    excludeTags: ['glibc-old', 'static'],
    baseConfidence: 'high',
    reason: 'Heap vuln + glibc 2.26–2.31 → corrupt tcache fd for arbitrary alloc',
    requiredLeaks: ['heap address (for safe-linking if 2.32+)'],
    suggestedTools: ['pwndbg bins', 'pwndbg vis_heap_chunks'],
  },
  {
    name: 'Fastbin Dup',
    techniqueId: 'double_free',
    requiredTags: ['double-free', 'glibc-old'],
    boostTags: ['heap-vuln'],
    excludeTags: ['static'],
    baseConfidence: 'high',
    reason: 'Double free + old glibc → fastbin duplication for arbitrary write',
    requiredLeaks: [],
    suggestedTools: ['pwndbg bins', 'pwntools'],
  },
  {
    name: 'Use-After-Free → VTable/Hook',
    techniqueId: 'use_after_free',
    requiredTags: ['uaf'],
    boostTags: ['heap-vuln', 'info-leak'],
    excludeTags: ['static'],
    baseConfidence: 'high',
    reason: 'UAF → reallocate freed object → overwrite vtable or hook pointer',
    requiredLeaks: ['heap layout', 'libc base'],
    suggestedTools: ['pwndbg heap', 'pwntools'],
  },
  {
    name: 'Tcache Dup (Double Free)',
    techniqueId: 'double_free',
    requiredTags: ['double-free', 'glibc-mid'],
    boostTags: ['heap-vuln'],
    excludeTags: ['glibc-old', 'static'],
    baseConfidence: 'high',
    reason: 'Double free in tcache range → tcache dup for arbitrary alloc',
    requiredLeaks: [],
    suggestedTools: ['pwndbg bins', 'pwntools'],
  },
  {
    name: 'House of Force',
    techniqueId: 'heap_exploit',
    requiredTags: ['heap-overflow', 'glibc-old'],
    boostTags: ['arb-write'],
    excludeTags: ['glibc-new', 'glibc-latest'],
    baseConfidence: 'medium',
    reason: 'Heap overflow + old glibc → corrupt top chunk for arbitrary alloc',
    requiredLeaks: ['heap base address'],
    suggestedTools: ['pwndbg vis_heap_chunks'],
  },

  // ── SANDBOX ──
  {
    name: 'ORW Chain (open/read/write)',
    techniqueId: 'sandbox_escape',
    requiredTags: ['seccomp', 'orw-allowed'],
    boostTags: ['rip-control', 'stack-bof'],
    excludeTags: [],
    baseConfidence: 'high',
    reason: 'Seccomp blocks execve but allows ORW → read flag via open/read/write chain',
    requiredLeaks: ['flag path'],
    suggestedTools: ['seccomp-tools', 'ROPgadget', 'pwntools'],
  },
  {
    name: 'Seccomp Bypass (variant syscalls)',
    techniqueId: 'sandbox_escape',
    requiredTags: ['seccomp', 'no-execve'],
    boostTags: [],
    excludeTags: ['orw-allowed'],
    baseConfidence: 'low',
    reason: 'Seccomp may have logical gaps — try execveat, clone, or other variants',
    requiredLeaks: [],
    suggestedTools: ['seccomp-tools', 'strace'],
  },

  // ── COMBINED / SPECIAL ──
  {
    name: 'Heap Spray + Shellcode',
    techniqueId: 'heap_spray',
    requiredTags: ['heap-vuln', 'nx-disabled'],
    boostTags: ['no-aslr'],
    excludeTags: ['seccomp'],
    baseConfidence: 'medium',
    reason: 'Heap vuln + NX disabled → spray heap with shellcode at predictable address',
    requiredLeaks: [],
    suggestedTools: ['pwntools', 'pwndbg vmmap'],
  },
  {
    name: 'Integer Overflow → BOF',
    techniqueId: 'buffer_overflow',
    requiredTags: ['int-overflow'],
    boostTags: ['stack-bof', 'heap-vuln'],
    excludeTags: [],
    baseConfidence: 'medium',
    reason: 'Integer overflow in size calculation → trigger buffer overflow',
    requiredLeaks: [],
    suggestedTools: ['GDB', 'pwntools'],
  },

  // ── NEW RULES ──

  // Off-by-One
  {
    name: 'Off-by-One → Heap Coalescing (Einherjar)',
    techniqueId: 'off_by_one',
    requiredTags: ['heap-vuln'],
    boostTags: ['heap-overflow', 'info-leak'],
    excludeTags: ['static'],
    baseConfidence: 'medium',
    reason: 'Off-by-one overflow into heap → corrupt PREV_INUSE → backward consolidation → overlapping chunks',
    requiredLeaks: ['heap address'],
    suggestedTools: ['pwndbg vis_heap_chunks', 'pwntools'],
  },
  {
    name: 'Off-by-One → Stack Pivot (RBP LSB)',
    techniqueId: 'off_by_one',
    requiredTags: ['stack-bof', 'nx-enabled'],
    boostTags: ['canary'],
    excludeTags: [],
    baseConfidence: 'medium',
    reason: 'Off-by-one overflow on stack → corrupt saved RBP LSB → pivot stack frame',
    requiredLeaks: ['stack layout'],
    suggestedTools: ['GDB', 'pwntools'],
  },

  // Blind Format String
  {
    name: 'Blind Format String → BROP-like Dump',
    techniqueId: 'format_string',
    requiredTags: ['format-string'],
    boostTags: ['network'],
    excludeTags: [],
    baseConfidence: 'low',
    reason: 'Format string with no output → use side-channel (timing/crash) to leak data byte-by-byte',
    requiredLeaks: [],
    suggestedTools: ['pwntools', 'timing analysis scripts'],
  },

  // SROP Rules
  {
    name: 'SROP → execve (large overflow)',
    techniqueId: 'srop',
    requiredTags: ['stack-bof', 'static'],
    boostTags: ['no-canary', 'rip-control'],
    excludeTags: ['seccomp'],
    baseConfidence: 'high',
    reason: 'Static binary with large overflow (~300 bytes) → SROP one-shot sets all registers for execve',
    requiredLeaks: [],
    suggestedTools: ['pwntools SigreturnFrame', 'ROPgadget'],
  },
  {
    name: 'SROP → ORW (seccomp bypass)',
    techniqueId: 'srop',
    requiredTags: ['seccomp', 'orw-allowed', 'stack-bof'],
    boostTags: ['no-canary', 'rip-control'],
    excludeTags: [],
    baseConfidence: 'high',
    reason: 'Seccomp blocks execve → SROP chains open/read/write via consecutive sigreturn frames',
    requiredLeaks: ['flag path'],
    suggestedTools: ['pwntools SigreturnFrame', 'seccomp-tools'],
  },

  // BROP Rules
  {
    name: 'BROP (Blind ROP)',
    techniqueId: 'brop',
    requiredTags: ['stack-bof', 'network'],
    boostTags: ['no-pie', 'nx-enabled'],
    excludeTags: ['pie', 'symbols'],
    baseConfidence: 'medium',
    reason: 'Remote forking server with BOF → brute-force gadgets → dump binary → build exploit',
    requiredLeaks: [],
    suggestedTools: ['pwntools', 'custom BROP scanner'],
  },

  // Stack Pivot
  {
    name: 'Stack Pivot (leave;ret)',
    techniqueId: 'stack_pivot',
    requiredTags: ['stack-bof', 'rip-control'],
    boostTags: ['nx-enabled', 'info-leak'],
    excludeTags: [],
    baseConfidence: 'medium',
    reason: 'Small overflow space → pivot RSP to controlled memory for full ROP chain',
    requiredLeaks: ['writable memory address for fake stack'],
    suggestedTools: ['ROPgadget (leave;ret)', 'pwndbg vmmap'],
  },

  // UAF Rules
  {
    name: 'UAF → VTable Hijack',
    techniqueId: 'use_after_free',
    requiredTags: ['uaf'],
    boostTags: ['info-leak', 'heap-vuln'],
    excludeTags: ['static'],
    baseConfidence: 'high',
    reason: 'UAF on C++ object → reallocate controlled data → overwrite vtable pointer → redirect virtual call',
    requiredLeaks: ['heap address'],
    suggestedTools: ['pwndbg heap', 'pwntools'],
  },
  {
    name: 'UAF → Tcache Metadata Corruption',
    techniqueId: 'use_after_free',
    requiredTags: ['uaf', 'glibc-mid'],
    boostTags: ['heap-vuln', 'info-leak'],
    excludeTags: ['static', 'glibc-old'],
    baseConfidence: 'high',
    reason: 'UAF in tcache range → corrupt fd pointer → tcache poisoning → arbitrary allocation',
    requiredLeaks: ['heap address (for safe-linking if 2.32+)'],
    suggestedTools: ['pwndbg bins', 'pwntools'],
  },

  // Tcache Stashing
  {
    name: 'Tcache Stashing Unlink',
    techniqueId: 'tcache_stashing',
    requiredTags: ['heap-vuln', 'glibc-mid'],
    boostTags: ['uaf', 'heap-overflow', 'arb-write'],
    excludeTags: ['static', 'glibc-old'],
    baseConfidence: 'medium',
    reason: 'Heap vuln + glibc 2.26-2.31 + calloc usage → corrupt smallbin bk → arbitrary write via stashing',
    requiredLeaks: ['heap address', 'libc base'],
    suggestedTools: ['pwndbg bins', 'pwntools'],
  },

  // eBPF Exploit
  {
    name: 'eBPF Verifier Bypass',
    techniqueId: 'ebpf_exploit',
    requiredTags: ['heap-vuln'],
    boostTags: ['arb-read', 'arb-write'],
    excludeTags: [],
    baseConfidence: 'low',
    reason: 'Requires CAP_BPF and vulnerable kernel → verifier bug → load malicious BPF → kernel R/W',
    requiredLeaks: ['kernel base (KASLR)'],
    suggestedTools: ['custom BPF bytecode assembler', 'exploit-db'],
  },

  // Kernel Priv Esc
  {
    name: 'modprobe_path Overwrite',
    techniqueId: 'modprobe_path',
    requiredTags: ['arb-write'],
    boostTags: ['seccomp'],
    excludeTags: [],
    baseConfidence: 'medium',
    reason: 'Arbitrary kernel write → overwrite modprobe_path → trigger unknown binary → root shell',
    requiredLeaks: ['kernel base'],
    suggestedTools: ['kernel exploit (C)', 'pwntools'],
  },
  {
    name: 'Kernel ROP Chain',
    techniqueId: 'kernel_rce',
    requiredTags: ['arb-write', 'rip-control'],
    boostTags: ['info-leak'],
    excludeTags: [],
    baseConfidence: 'low',
    reason: 'Kernel arbitrary execution → ROP chain → commit_creds(prepare_kernel_cred(0)) → root',
    requiredLeaks: ['kernel base (KASLR bypass)'],
    suggestedTools: ['ROPgadget (on vmlinux)', 'pwntools'],
  },

  // ret2csu
  {
    name: 'ret2csu (no pop rdx available)',
    techniqueId: 'ret2csu',
    requiredTags: ['stack-bof', 'dynamic'],
    boostTags: ['nx-enabled', 'no-canary'],
    excludeTags: ['static'],
    baseConfidence: 'high',
    reason: 'x64 ELF, no pop rdx gadget → use __libc_csu_init to control rdx/rsi/rdi',
    requiredLeaks: [],
    suggestedTools: ['ropper', 'pwntools', 'objdump'],
  },

  // ret2dlresolve
  {
    name: 'ret2dl-resolve (no libc leak)',
    techniqueId: 'ret2dlresolve',
    requiredTags: ['stack-bof', 'no-pie', 'dynamic'],
    boostTags: ['no-relro', 'partial-relro'],
    excludeTags: ['full-relro', 'static'],
    baseConfidence: 'medium',
    reason: 'No PIE + dynamic + writable GOT → forge reloc/sym/strtab → resolve system() without leak',
    requiredLeaks: [],
    suggestedTools: ['pwntools Ret2dlresolvePayload', 'readelf'],
  },
];

// ─── RECOMMENDATION ENGINE ───

export function getExploitRecommendations(selectedTags: Set<string>): ExploitRecommendation[] {
  if (selectedTags.size === 0) return [];

  const results: ExploitRecommendation[] = [];

  for (const rule of EXPLOIT_RULES) {
    // Check all required tags are present
    const allRequired = rule.requiredTags.every(t => selectedTags.has(t));
    if (!allRequired) continue;

    // Check no exclude tags are present
    const anyExcluded = rule.excludeTags.some(t => selectedTags.has(t));
    if (anyExcluded) continue;

    // Calculate confidence
    let confidence = rule.baseConfidence;
    const boostCount = rule.boostTags.filter(t => selectedTags.has(t)).length;
    if (confidence === 'medium' && boostCount >= 2) confidence = 'high';
    if (confidence === 'low' && boostCount >= 2) confidence = 'medium';

    results.push({
      techniqueId: rule.techniqueId,
      name: rule.name,
      confidence,
      reason: rule.reason,
      requiredLeaks: rule.requiredLeaks,
      suggestedTools: rule.suggestedTools,
    });
  }

  // Sort: high > medium > low
  const order = { high: 0, medium: 1, low: 2 };
  results.sort((a, b) => order[a.confidence] - order[b.confidence]);

  return results;
}

export const RECON_CATEGORIES = {
  basic: { label: 'Basic Information', icon: '📋', color: '#00d9ff' },
  protections: { label: 'Binary Protections', icon: '🛡️', color: '#a78bfa' },
  analysis: { label: 'Vulnerability Analysis', icon: '🔍', color: '#f97316' },
  runtime: { label: 'Runtime Environment', icon: '⚡', color: '#10b981' },
} as const;
