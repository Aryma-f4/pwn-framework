export interface ExploitationPath {
  name: string;
  description: string;
  steps: string[];
  tools: string[];
  codeSnippet?: string;
  applicableLibc?: string;
  references?: string[];
}

export interface TechniqueDetails {
  id: string;
  name: string;
  category: 'recon' | 'mitigation' | 'technique' | 'leaf';
  class: string;
  description: string;
  
  // Comprehensive preconditions
  preconditions: {
    summary: string;
    required: string[];
    detectionSteps: string[];
    offsetDiscovery?: {
      [key: string]: string;
    };
  };
  
  // Multiple exploitation paths
  exploitationPaths: ExploitationPath[];
  
  // Post-exploitation
  postconditions: {
    successIndicators: string[];
    artifacts: string[];
  };
  
  // Operator workflow
  operatorChecklist: string[];
  
  // Filtering tags
  vulnerabilityTypes: string[];
  
  // References and write-ups
  references: {
    tool?: string;
    url?: string;
    description?: string;
  }[];
  
  children?: string[];
}

// Core tools reference library
export const CORE_TOOLS = {
  checksec: 'Best all-in-one mitigation scanner',
  readelf: 'ELF headers, sections, dynamic entries, RELRO, PIE',
  objdump: 'Disassembly, symbol tables, GOT/PLT layout',
  file: 'Basic architecture & ELF type detection',
  pwndbg: 'Enriched GDB: vmmap, heap, canary, telescope',
  GEF: 'GDB Enhanced Features: heap-analysis-helper, pattern',
  PEDA: 'Pattern generation, searchmem, context',
  gdb: 'Base debugger',
  'radare2/rabin2': 'Fast static + dynamic analysis alternative',
  pwntools: 'Exploit framework: cyclic, flat, fit, ELF, ROP, tubes',
  ROPgadget: 'ROP chain gadget search',
  ropper: 'Alternative gadget finder (cleaner output)',
  one_gadget: 'Libc execve one-gadget finder',
  'libc-database': 'Offline libc version lookup by symbol offsets',
  'libc.rip': 'Online libc symbol resolver',
  'seccomp-tools': 'Dump & analyze seccomp BPF filters',
  ltrace: 'Library call tracer',
  strace: 'Syscall tracer',
  strings: 'Static string extraction',
  nm: 'Symbol table dump',
  ldd: 'Shared library dependency listing',
  strip: 'Symbol strip detection',
  'vmmap (pwndbg)': 'Runtime memory map with permissions',
};

export const PWN_KNOWLEDGE_BASE: Record<string, TechniqueDetails> = {
  stack_buffer_overflow: {
    id: 'stack_buffer_overflow',
    name: 'Stack-Based Buffer Overflow (SBOF)',
    category: 'technique',
    class: 'Memory Corruption',
    description: 'Exploits by overwriting stack buffers to redirect execution flow and achieve RCE',
    
    preconditions: {
      summary: 'A fixed-size stack buffer exists and user-controlled input is written into it without proper length validation.',
      required: [
        'Vulnerable input function: gets(), read() with oversized count, scanf("%s"), strcpy(), strcat(), fgets() with wrong size',
        'Target buffer allocated on stack frame (local variable)',
        'Input length controllable by attacker (minimum buffer_size + 8 bytes for 64-bit RIP overwrite)',
        'No stack canary OR canary value is leaked/bypassable',
        'NX disabled (for shellcode) OR ROP gadgets/ret2libc available',
        'ASLR known or leaked if PIE/libc addresses needed'
      ],
      detectionSteps: [
        'Run: checksec --file=./binary → note canary/NX/PIE/RELRO status',
        'In GDB: disas <vuln_function> → look for call to gets/read/scanf',
        'Use cyclic (pwntools) or pattern_create to determine exact offset to RIP',
        'Send cyclic(200) payload → examine crash → extract RIP overwrite offset'
      ],
      offsetDiscovery: {
        'pwntools': 'cyclic(200) → crash → cyclic_find(core.read(rsp, 4))',
        'pwndbg': 'cyclic 200 → run → cyclic -l $rsp',
        'GEF': 'pattern create 200 → run → pattern search $rsp',
        'PEDA': 'pattern create 200 → run → pattern search'
      }
    },
    
    exploitationPaths: [
      {
        name: 'ret2shellcode (NX disabled, no PIE or leak available)',
        description: 'Inject executable shellcode directly into the buffer and redirect execution to it',
        steps: [
          'Find writable+executable memory region (vmmap in pwndbg)',
          'Inject shellcode into the buffer or adjacent memory',
          'Overwrite RIP with buffer/shellcode address',
          'Use NOP sled (0x90) to increase hit probability'
        ],
        tools: ['pwntools (shellcraft, asm)', 'pwndbg vmmap', 'objdump -d', 'msfvenom'],
        codeSnippet: `shellcode = asm(shellcraft.sh())
padding = b'A' * offset
payload = shellcode.ljust(offset, b'\\x90') + p64(buf_addr)
p.send(payload)`,
        references: [
          { description: 'PwnTools Shellcraft Documentation' },
          { tool: 'msfvenom', description: 'Metasploit shellcode generator' }
        ]
      },
      {
        name: 'ret2libc (NX enabled, ASLR off or leak available)',
        description: 'Chain libc functions (system) with controlled arguments to spawn shell',
        steps: [
          'Find offset to RIP using cyclic pattern',
          'Locate "pop rdi; ret" gadget for first argument setup',
          'Find /bin/sh string in libc address space',
          'Build chain: pop_rdi → &"/bin/sh" → system()',
          'If ASLR: leak libc via puts(got_entry), compute base = leak - symbol_offset'
        ],
        tools: ['ROPgadget', 'ropper', 'pwntools ROP class', 'one_gadget', 'libc.rip', 'libc-database'],
        codeSnippet: `rop = ROP(libc)
sh_addr = next(libc.search(b'/bin/sh'))
rop.call('system', [sh_addr])
payload = b'A' * offset + rop.chain()
p.send(payload)`,
        applicableLibc: 'All versions',
        references: [
          { description: 'ret2libc attack technique', url: 'https://ctf101.org/binary-exploitation/return-oriented-programming/' },
          { tool: 'one_gadget', description: 'Single-gadget RCE finder for libc' }
        ]
      },
      {
        name: 'ret2plt (call PLT stub for information leak)',
        description: 'Leak libc base by calling puts(GOT_entry) to enable ASLR bypass',
        steps: [
          'Locate puts@plt or printf@plt in binary PLT section',
          'Call puts@plt with GOT entry address to leak libc address',
          'Compute libc base: base = leak - known_offset_in_libc',
          'Return to vulnerable function for second stage exploitation',
          'Execute final ROP chain with computed libc addresses'
        ],
        tools: ['pwntools ELF (elf.plt, elf.got)', 'ROPgadget', 'pwntools ROP', 'readelf'],
        references: [
          { description: 'Two-stage exploitation with information leaks' }
        ]
      },
      {
        name: 'ret2syscall / SROP (no libc available)',
        description: 'Direct syscall gadgets or signal frame manipulation for RCE without libc',
        steps: [
          'Find "syscall; ret" and "pop rax; ret" gadgets via ROPgadget',
          'Set rax=59 (execve), rdi=&"/bin/sh", rsi=0, rdx=0',
          'Alternatively: trigger SIGSEGV → use sigreturn syscall to craft fake signal frame',
          'SROP can bypass restrictions where function calls are filtered'
        ],
        tools: ['ROPgadget', 'ropper', 'pwntools SigreturnFrame'],
        applicableLibc: 'Stripped binaries or libc unavailable',
        references: [
          { description: 'SROP: Exploiting the Processor using Signals' }
        ]
      }
    ],
    
    postconditions: {
      successIndicators: [
        'RIP/EIP register controlled and redirected to attacker payload',
        'Shell spawned (interactive or reverse shell)',
        'Arbitrary code execution achieved with target process privileges'
      ],
      artifacts: [
        'Core dump showing controlled instruction pointer',
        'Shell session with target user privileges',
        'Flag file read in CTF context'
      ]
    },
    
    operatorChecklist: [
      '[ ] Run checksec → record canary/NX/PIE/RELRO status',
      '[ ] Identify vulnerable function via disassembly (objdump / GDB)',
      '[ ] Calculate exact RIP offset using cyclic payload + crash analysis',
      '[ ] Determine exploitation path based on protections (ASLR, canary, NX)',
      '[ ] Find required ROP gadgets (ROPgadget / ropper)',
      '[ ] Identify libc version if needed (ldd, libc.rip, one_gadget)',
      '[ ] Craft pwntools exploit script with correct padding + ROP chain',
      '[ ] Test locally with ASLR disabled (echo 0 > /proc/sys/kernel/randomize_va_space)',
      '[ ] If ASLR enabled: leak addresses → recompute offsets dynamically',
      '[ ] Test against remote target with correct libc version matched'
    ],
    
    vulnerabilityTypes: ['stack', 'buffer'],
    
    references: [
      { tool: 'pwntools', description: 'Python exploitation framework' },
      { tool: 'pwndbg', description: 'Enhanced GDB plugin for exploit development', url: 'https://github.com/pwndbg/pwndbg' },
      { tool: 'ROPgadget', description: 'ROP chain gadget search utility' },
      { description: 'CTF101: Binary Exploitation', url: 'https://ctf101.org/binary-exploitation/' }
    ]
  },

  format_string_vulnerability: {
    id: 'format_string_vulnerability',
    name: 'Format String Vulnerability (FSB)',
    category: 'technique',
    class: 'Format String Exploitation',
    description: 'User-controlled data passed directly as format string to printf/fprintf enabling arbitrary read/write',
    
    preconditions: {
      summary: 'User-controlled data is passed directly as the format string argument to printf, fprintf, sprintf, etc.',
      required: [
        'printf(user_input) instead of printf("%s", user_input)',
        'Attacker controls the format string content completely',
        'Binary must be running (FSB is runtime-only attack)',
        'Stack readable: %p/%x chains can dump stack contents',
        'Write primitive: %n, %hn, %hhn available (usually not restricted on Linux)'
      ],
      detectionSteps: [
        'Send "%p.%p.%p.%p.%p.%p.%p.%p" — if addresses print back, FSB confirmed',
        'Send "%7$p" to read specific stack argument by index',
        'Send AAAA.%p.%p... to locate where input appears on stack (offset discovery)',
        'In GDB: set breakpoint at printf, inspect rsi/rdx/... (format arg registers)'
      ],
      offsetDiscovery: {
        'manual': 'Send "AAAA" + ".%p"*N until 0x41414141 appears in output',
        'pwntools': 'for i in range(1,50): p.sendline(f"%{i}$p"); leak = p.recvline()'
      }
    },
    
    exploitationPaths: [
      {
        name: 'Arbitrary Read (info-leak)',
        description: 'Leak sensitive data from stack/memory (canary, PIE base, libc base)',
        steps: [
          'Use %<N>$p or %<N>$s to read N-th printf argument position',
          'Target: stack canary (usually at fixed offset from format string on stack)',
          'Target: saved RIP on stack → compute binary base (if PIE)',
          'Target: libc function pointer on stack → compute libc base',
          'Chain leaks: canary + PIE + libc for multi-stage exploitation'
        ],
        tools: ['pwntools fmtstr_payload', 'manual %N$p probing', 'pwndbg telescope'],
        codeSnippet: `for i in range(1, 20):
    p.sendline(f'%{i}$p')
    leak = p.recvline()
    if b'0x' in leak:
        print(f'Position {i}: {leak}')`,
        references: [
          { description: 'Format String Vulnerability - CTF101', url: 'https://ctf101.org/binary-exploitation/format-string/' }
        ]
      },
      {
        name: 'Arbitrary Write via %n',
        description: 'Overwrite memory locations (GOT, hooks, return addresses)',
        steps: [
          'Use %<value>c%<N>$n to write "value" bytes count to address at position N',
          '%n writes 4 bytes (int), %hn writes 2 bytes, %hhn writes 1 byte (most precise)',
          'Common targets: GOT entry of called function, return address, __malloc_hook, __exit_funcs',
          'Pad with %c.%c... to reach desired byte count before %n'
        ],
        tools: ['pwntools fmtstr_payload(offset, {target: value})', 'manual calculation', 'pwndbg got command'],
        codeSnippet: `# Write 0x1234 to GOT entry at position 6
payload = fmtstr_payload(6, {got_addr: system_addr}, numbwritten=0)
p.sendline(payload)`,
        applicableLibc: 'Most versions; hooks removed in libc 2.34+',
        references: [
          { description: 'House of Spirit via Format String' }
        ]
      },
      {
        name: 'Canary Leak + Stack Overflow (combined attack)',
        description: 'Use FSB to leak canary, then perform SBOF with correct canary value',
        steps: [
          'Leak canary via %<N>$p at known canary stack offset',
          'Leak PIE base via saved RIP if needed',
          'Leak libc via stored pointer if needed',
          'Trigger buffer overflow with correct canary spliced into payload',
          'Combine SBOF and FSB for maximum bypass coverage'
        ],
        tools: ['pwntools', 'pwndbg canary command'],
        references: [
          { description: 'Multi-layer exploit techniques' }
        ]
      }
    ],
    
    postconditions: {
      successIndicators: [
        'Arbitrary memory read confirmed (addresses printed back)',
        'Target memory location overwritten with attacker-controlled value',
        'Control flow redirected (GOT hijack, return address overwrite)',
        'Shell obtained or flag read via modified function pointer'
      ],
      artifacts: [
        'Leaked canary/PIE/libc values in exploit output',
        'Overwritten GOT verified via pwndbg "got" command',
        'Shell session obtained'
      ]
    },
    
    operatorChecklist: [
      '[ ] Confirm FSB: send "%p.%p.%p" and verify address leak from output',
      '[ ] Discover format string stack offset (where input appears as printf argument)',
      '[ ] Leak canary if checksec shows canary=yes (CRITICAL)',
      '[ ] Leak PIE base if PIE enabled via saved RIP on stack',
      '[ ] Leak libc base via GOT pointer on stack or %s GOT read',
      '[ ] Identify write target based on RELRO status (GOT, hook, ret addr)',
      '[ ] Use pwntools fmtstr_payload() or craft manual %<N>$<width>hhn chain',
      '[ ] Verify write in local GDB before sending to remote',
      '[ ] Trigger overwritten function to execute payload (shell/one_gadget)'
    ],
    
    vulnerabilityTypes: ['format'],
    
    references: [
      { tool: 'pwntools', description: 'fmtstr_payload for automated FSB exploitation' },
      { description: 'Format String Attack - Wikipedia', url: 'https://en.wikipedia.org/wiki/Printf_format_string_attack' },
      { description: 'Format String Vulnerability Exploitation', url: 'https://ctf101.org/binary-exploitation/format-string/' }
    ]
  },

  heap_buffer_overflow: {
    id: 'heap_buffer_overflow',
    name: 'Heap Buffer Overflow',
    category: 'technique',
    class: 'Heap Exploitation',
    description: 'Overflow heap-allocated chunks to corrupt metadata or adjacent objects',
    
    preconditions: {
      summary: 'Data written to heap-allocated chunk overflows into adjacent chunk metadata or data, corrupting allocator structures',
      required: [
        'Heap allocation (malloc/calloc/realloc/new) used for user data',
        'Input written without size check, allowing overflow into next chunk header',
        'Attacker controls overflow length and content',
        'malloc version determines available techniques (check via: strings libc.so | grep GNU C)'
      ],
      detectionSteps: [
        'In GDB: heap (pwndbg) → inspect chunk layout',
        'Send large input to heap-stored buffer → check if next chunk prev_size/size corrupted',
        'Trigger free() after overflow → "corrupted double-linked list" indicates successful write',
        'Use pwndbg "vis_heap_chunks" for visual chunk layout and metadata'
      ],
      offsetDiscovery: {
        'pwndbg': 'heap → chunks → identify target chunk size field offset',
        'manual': 'Calculate: buffer_size + 16 (chunk header size) = overflow trigger point'
      }
    },
    
    exploitationPaths: [
      {
        name: 'fastbin dup / tcache dup (double free)',
        description: 'Free same chunk twice to create overlapping allocations',
        steps: [
          'Free same chunk twice → chunk appears twice in bin',
          'Allocate twice to get overlapping chunks with controlled content',
          'Overwrite fd pointer to target address (use safe-linking XOR if needed)',
          'Allocate until fake chunk returned at target address',
          'Write controlled payload to arbitrary memory'
        ],
        tools: ['pwndbg bins', 'pwntools malloc_chunk parsing'],
        applicableLibc: '< 2.26 for fastbin; tcache dup in 2.26-2.28 (no key check)',
        codeSnippet: `free(chunk)  # First free
free(chunk)  # Double free → chunk in bin twice
malloc(size) # Allocate → get original chunk
malloc(size) # Allocate → get chunk with corrupted fd`,
        references: [
          { description: 'How2Heap: fastbin_dup', url: 'https://github.com/shellphish/how2heap' }
        ]
      },
      {
        name: 'tcache poisoning (libc 2.26+)',
        description: 'Corrupt tcache bin to allocate at arbitrary address',
        steps: [
          'Free chunk into tcache',
          'Overflow into tcache entry and corrupt fd pointer to &target - 0x10',
          'Allocate twice: first returns original chunk, second returns fake chunk at target',
          'Write controlled data to arbitrary address (libc 2.32+ requires safe-linking bypass)',
          'For safe-linking (2.32+): fd_stored = (chunk_addr >> 12) XOR target'
        ],
        tools: ['pwndbg bins', 'pwndbg vis_heap_chunks', 'pwntools'],
        applicableLibc: '2.26 to 2.31 (no safe-linking); 2.32+ with safe-linking',
        references: [
          { description: 'How2Heap: tcache_poisoning' },
          { description: 'Safe-linking in glibc', url: 'https://www.qualys.com/2019/12/18/cve-2019-19363.txt' }
        ]
      },
      {
        name: 'House of Force (libc < 2.29)',
        description: 'Corrupt top chunk size to allocate at arbitrary address',
        steps: [
          'Overflow into top chunk size field, set to 0xffffffffffffffff',
          'Allocate large chunk with calculated size to advance top pointer to target',
          'Next allocation returns chunk at target address',
          'Write controlled data to target via standard malloc/free workflow'
        ],
        tools: ['pwndbg vis_heap_chunks', 'pwntools'],
        applicableLibc: '< 2.29',
        references: [
          { description: 'House of Force technique' }
        ]
      }
    ],
    
    postconditions: {
      successIndicators: [
        'Heap chunk metadata corrupted (size/fd/bk fields)',
        'Arbitrary allocation primitive achieved',
        'Write/read to controlled memory location',
        'Code execution via __malloc_hook or similar'
      ],
      artifacts: [
        'pwndbg "heap" command shows corrupted chunk',
        'Successful allocation at target address',
        'Shell session'
      ]
    },
    
    operatorChecklist: [
      '[ ] Identify heap allocation and overflow vector',
      '[ ] Run checksec → note libc version (determines applicable techniques)',
      '[ ] In GDB: heap → vis_heap_chunks → understand target chunk layout',
      '[ ] Determine libc version (ldd, strings, or libc.rip)',
      '[ ] Select exploitation path (fastbin/tcache/House of Force based on version)',
      '[ ] Craft overflow payload to corrupt target metadata field',
      '[ ] Test locally: trigger malloc → verify arbitrary address allocation',
      '[ ] For safe-linking bypass: leak heap address first',
      '[ ] Write payload to allocated target address',
      '[ ] Trigger code execution via overwritten hook or function pointer'
    ],
    
    vulnerabilityTypes: ['heap'],
    
    references: [
      { tool: 'how2heap', description: 'Heap exploitation techniques repository', url: 'https://github.com/shellphish/how2heap' },
      { tool: 'pwndbg', description: 'heap command for visualizing malloc structures' },
      { description: 'Heap Exploitation CTF101', url: 'https://ctf101.org/binary-exploitation/heap/' }
    ]
  },

  sandbox_escape: {
    id: 'sandbox_escape',
    name: 'Sandbox / Seccomp Escape',
    category: 'technique',
    class: 'Sandbox Bypass',
    description: 'Bypass seccomp filters and sandboxes to achieve code execution',
    
    preconditions: {
      summary: 'Process is restricted by seccomp BPF filter limiting available syscalls',
      required: [
        'seccomp-bpf filter installed via prctl(PR_SET_SECCOMP)',
        'Attacker must determine allowed syscalls (dump via seccomp-tools)',
        'Standard execution syscalls (execve) typically blocked',
        'Often allows: open, read, write, exit (ORW techniques)',
        'File descriptors may be pre-opened or seekable'
      ],
      detectionSteps: [
        'Run: seccomp-tools dump ./binary → inspect BPF rules',
        'Run: strace ./binary 2>&1 | grep -E "prctl|seccomp"',
        'Attempt execve syscall → SIGSYS signal indicates blocked',
        'Check available syscalls via seccomp-tools output'
      ]
    },
    
    exploitationPaths: [
      {
        name: 'ORW (open/read/write) chain',
        description: 'Read flag file using open/read/write syscalls instead of execve',
        steps: [
          'Identify allowed syscalls: typically open(2), read(3), write(4)',
          'Build ROP chain: open(flag_path) → read(fd, buf, 0x100) → write(1, buf, 0x100)',
          'Flag content written to stdout, readable to attacker',
          'Chain each syscall with proper argument registers (rax, rdi, rsi, rdx)'
        ],
        tools: ['ROPgadget', 'pwntools SigreturnFrame', 'seccomp-tools'],
        codeSnippet: `rop = ROP(binary)
rop(rax=2)  # open syscall
rop(rdi=flag_addr, rsi=0, rdx=0)  # filename, O_RDONLY, 0
rop(syscall)
# ... repeat for read(3) and write(4)`,
        references: [
          { description: 'ORW technique for sandboxed exploitation' }
        ]
      },
      {
        name: 'Seccomp filter bypass (vulnerable policies)',
        description: 'Exploit logical flaws in BPF filter rules',
        steps: [
          'Analyze seccomp-tools output for logical gaps',
          'Some filters allow execve but block execveat, or vice versa',
          'Some allow clone but block fork (or similar variant syscalls)',
          'Craft chain using allowed variant syscall',
          'Test each variant systematically'
        ],
        tools: ['seccomp-tools', 'ltrace', 'strace'],
        references: [
          { description: 'Seccomp bypass via logical flaws' }
        ]
      }
    ],
    
    postconditions: {
      successIndicators: [
        'Seccomp SIGSYS no longer triggered for required syscalls',
        'Flag file read and output captured',
        'Code execution achieved within sandbox constraints'
      ],
      artifacts: [
        'Flag content in stdout/stderr',
        'seccomp-tools dump showing allowed syscalls',
        'ORW ROP chain execution confirmed'
      ]
    },
    
    operatorChecklist: [
      '[ ] Run seccomp-tools dump → document allowed syscalls',
      '[ ] Identify if execve is available (usually not in CTF)',
      '[ ] If blocked: design ORW chain (open/read/write)',
      '[ ] Find gadgets: syscall, pop rax, pop rdi, pop rsi, pop rdx',
      '[ ] Build ROP chain: open(flag) → read(fd,buf,size) → write(1,buf,size)',
      '[ ] Verify each syscall number (rax=2 open, 3 read, 4 write)',
      '[ ] Test locally: confirm flag readable via stdout',
      '[ ] Alternative: check for execveat, execve with args, clone variants',
      '[ ] Send exploit to remote target'
    ],
    
    vulnerabilityTypes: ['sandbox'],
    
    references: [
      { tool: 'seccomp-tools', description: 'Dump and analyze seccomp BPF filters', url: 'https://github.com/david942j/seccomp-tools' },
      { description: 'Seccomp Exploitation Techniques', url: 'https://lkmidas.github.io/posts/20210105-seccomp/' },
      { tool: 'pwntools', description: 'ROP gadget chaining for syscall automation' }
    ]
  }
};

// Create flat list for backward compatibility
export const TECHNIQUES_LIST = Object.values(PWN_KNOWLEDGE_BASE);
