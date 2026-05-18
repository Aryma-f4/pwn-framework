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
  },

  ret2csu: {
    id: 'ret2csu',
    name: 'Ret2csu (Return-to-csu)',
    category: 'technique',
    class: 'ret2csu',
    description: 'A ROP technique that uses the universally available __libc_csu_init gadgets in dynamically linked x64 ELF binaries to populate RDX, RSI, RDI, and call an arbitrary function pointer. Extremely useful when standard pop rdx/rsi/rdi gadgets are missing.',
    preconditions: {
      summary: 'Dynamically linked x64 ELF binary with a buffer overflow, lacking standard ROP gadgets (specifically pop rdx).',
      required: [
        'Buffer overflow allowing RIP control',
        'x64 dynamically linked ELF binary',
        '__libc_csu_init function present in the binary (typically present by default in gcc up to ~v11)'
      ],
      detectionSteps: [
        'Run `objdump -d binary | grep __libc_csu_init` to verify existence',
        'Use ROPgadget or ropper to search for `pop rdx`. If none exist, ret2csu is a strong candidate.'
      ]
    },
    exploitationPaths: [
      {
        name: 'Standard ret2csu sequence',
        description: 'Execute the two-stage gadget from __libc_csu_init to call a function with 3 controlled arguments.',
        steps: [
          'Locate the two gadgets in __libc_csu_init (Gadget 1: pop rbx, rbp, r12, r13, r14, r15; Gadget 2: mov rdx, r15; mov rsi, r14; mov edi, r13d; call [r12+rbx*8]).',
          'Chain Gadget 1 to setup registers: rbx=0, rbp=1, r12=function_ptr, r13=arg1(rdi), r14=arg2(rsi), r15=arg3(rdx).',
          'Chain into Gadget 2. It will set rdx, rsi, rdi, and call [r12].',
          'Since rbx=0 and rbp=1, the subsequent cmp and jne will fall through, popping 7 values (add rsp, 8 and 6 pops).',
          'Pad the ROP chain with 7 * 8 = 56 bytes of junk, then place the next ROP gadget address.'
        ],
        tools: ['ropper', 'pwndbg', 'pwntools'],
        codeSnippet: `def ret2csu(func_ptr, arg1, arg2, arg3):
    # csu_gadget_1: pop rbx, rbp, r12, r13, r14, r15, ret
    # csu_gadget_2: mov rdx, r15; mov rsi, r14; mov edi, r13d; call [r12+rbx*8]
    payload = p64(csu_gadget_1)
    payload += p64(0)          # rbx = 0
    payload += p64(1)          # rbp = 1
    payload += p64(func_ptr)   # r12 = pointer to function to call
    payload += p64(arg1)       # r13 -> rdi
    payload += p64(arg2)       # r14 -> rsi
    payload += p64(arg3)       # r15 -> rdx
    payload += p64(csu_gadget_2)
    payload += b'JUNKJUNK' * 7 # padding for the pops after call
    return payload`
      }
    ],
    postconditions: {
      successIndicators: ['Target function executed with correct 3 arguments'],
      artifacts: ['Stack state shifted by 56 bytes post-execution']
    },
    operatorChecklist: [
      '[ ] Verify __libc_csu_init exists (not present in very recent gcc versions)',
      '[ ] Find Gadget 1 (pops) and Gadget 2 (movs and call)',
      '[ ] Identify a pointer to the function you want to call (r12 must point to a POINTER to the function, e.g., a GOT entry)',
      '[ ] Build the chain setting rbx=0, rbp=1',
      '[ ] Account for the 56 bytes of junk after the gadget completes'
    ],
    vulnerabilityTypes: ['stack', 'rop'],
    references: [
      { description: 'Return-to-csu (ret2csu) tutorial', url: 'https://ropemporium.com/guide.html' }
    ]
  },

  ret2dlresolve: {
    id: 'ret2dlresolve',
    name: 'Return-to-dl-resolve',
    category: 'technique',
    class: 'ret2dlresolve',
    description: 'A technique that exploits the lazy binding mechanism of the dynamic linker (_dl_runtime_resolve). By forging Elf32_Rel/Elf64_Rela, Elf32_Sym/Elf64_Sym, and string table entries in memory, an attacker forces the dynamic linker to resolve and execute an arbitrary function (like system) instead of a legitimate one, all without needing a libc leak.',
    preconditions: {
      summary: 'Dynamically linked ELF binary with NO RELRO or Partial RELRO, and a buffer overflow large enough to hold forged structures.',
      required: [
        'Buffer overflow allowing RIP control and significant payload space (>100 bytes)',
        'Known writable memory area at a fixed address (to place forged structures)',
        'Partial RELRO or No RELRO (Full RELRO resolves all symbols at startup, removing _dl_runtime_resolve)'
      ],
      detectionSteps: [
        'Run `checksec` to verify RELRO (must not be Full)',
        'Run `checksec` to verify PIE (typically needs No PIE to have a known writable address like .bss)'
      ]
    },
    exploitationPaths: [
      {
        name: 'Forging dynamic linker structures (32-bit/64-bit)',
        description: 'Forge Reloc, Sym, and StrTab entries to trick _dl_runtime_resolve into resolving system().',
        steps: [
          'Identify the address of the PLT0 entry (pushes link_map and jumps to _dl_runtime_resolve).',
          'Calculate the reloc_offset such that .rel.plt + reloc_offset points to your forged Reloc structure in writable memory.',
          'Forge a Reloc structure. Its r_info field must contain a sym_offset pointing to your forged Symbol structure.',
          'Forge a Symbol structure. Its st_name field must contain a string offset pointing to the string "system" in your forged string table.',
          'Build ROP chain: push arg1 (e.g., "/bin/sh" address), jump to PLT0, push reloc_offset.',
          'The dynamic linker will read your forged structures, resolve "system", and execute it with your argument.'
        ],
        tools: ['pwntools (Ret2dlresolvePayload)', 'readelf'],
        codeSnippet: `// Using pwntools simplifies this massively:
elf = ELF('./binary')
rop = ROP(elf)
dlresolve = Ret2dlresolvePayload(elf, symbol="system", args=["/bin/sh"])
rop.read(0, dlresolve.data_addr) # read payload into bss
rop.ret2dlresolve(dlresolve)     # trigger dl_resolve
payload = fit({ offset: rop.chain() })
io.sendline(payload)
io.sendline(dlresolve.payload)`
      }
    ],
    postconditions: {
      successIndicators: ['system("/bin/sh") executed without leaking libc'],
      artifacts: ['Forged ELF structures in .bss or other writable section']
    },
    operatorChecklist: [
      '[ ] Verify binary is dynamically linked and NOT Full RELRO',
      '[ ] Find a known, writable memory address (e.g., end of .bss)',
      '[ ] Calculate offsets for Reloc, Sym, and StrTab',
      '[ ] Ensure no bad characters in offsets if input is string-based',
      '[ ] Forge the payload (highly recommend using pwntools Ret2dlresolvePayload)',
      '[ ] Execute ROP chain to trigger PLT0 with forged reloc_offset'
    ],
    vulnerabilityTypes: ['stack', 'rop', 'dynamic-linking'],
    references: [
      { tool: 'pwntools Ret2dlresolvePayload', url: 'https://docs.pwntools.com/en/stable/rop/ret2dlresolve.html' }
    ]
  },

  fsop_exploit: {
    id: 'fsop_exploit',
    name: 'File Stream Oriented Programming (FSOP)',
    category: 'technique',
    class: 'fsop',
    description: 'Exploitation technique that corrupts the internal fields and vtables of glibc _IO_FILE structures (like stdin, stdout, stderr, or dynamically opened files). By modifying the _IO_jump_t vtable or internal pointers, attackers can hijack control flow when file stream operations (like fread, fwrite, or exit/abort flushing) occur.',
    preconditions: {
      summary: 'Ability to overwrite a _IO_FILE structure in memory (e.g., via heap overflow, UAF, or arbitrary write).',
      required: [
        'Memory corruption primitive targeting the heap (where dynamic files live) or libc data section (where stdout/stderr live)',
        'Knowledge of glibc version (critical for vtable mitigation bypasses)'
      ],
      detectionSteps: [
        'Identify arbitrary write or heap overflow',
        'Check if binary uses file operations or if you can trigger exit()/abort() which flushes all open streams via _IO_list_all'
      ]
    },
    exploitationPaths: [
      {
        name: 'Classic FSOP (glibc < 2.24)',
        description: 'Directly overwrite the vtable pointer of a _IO_FILE structure.',
        steps: [
          'Overwrite the _IO_FILE structure in memory.',
          'Set the vtable pointer (at the end of the struct) to point to a forged vtable in memory you control.',
          'Place the address of system() or a one_gadget at the offset of the function that will be called (e.g., _IO_file_overflow).',
          'Trigger a stream operation or exit().'
        ]
      },
      {
        name: 'vtable Mitigation Bypass (House of Apple / wide data)',
        description: 'Exploit newer glibc versions (2.24+) that validate vtables against the read-only __libc_IO_vtables section.',
        steps: [
          'Since you cannot point the vtable to your own forged table, point it to an existing but differently purposed vtable within the valid section (e.g., _IO_wstr_jumps).',
          'Forge the _wide_data structure pointer within the _IO_FILE to point to controlled memory.',
          'When a wide-character operation is triggered, the execution will follow the pointers in your forged _wide_data struct, eventually calling an arbitrary function.'
        ]
      }
    ],
    postconditions: {
      successIndicators: ['Control flow hijacked during I/O operation or exit()'],
      artifacts: ['Corrupted _IO_FILE structures in libc or heap']
    },
    operatorChecklist: [
      '[ ] Determine glibc version to identify active vtable mitigations',
      '[ ] Identify which _IO_FILE to corrupt (stdout, stderr, or heap file)',
      '[ ] Setup the forged structure with correct magic numbers and flags to bypass initial validation checks',
      '[ ] Setup the forged vtable or wide_data structure',
      '[ ] Trigger the flush or operation (e.g., via return from main, abort(), or puts())'
    ],
    vulnerabilityTypes: ['heap', 'arbitrary-write', 'fsop'],
    references: [
      { description: 'FSOP Introduction', url: 'https://ctf-wiki.mahaloz.re/pwn/linux/io_file/fsop/' },
      { description: 'House of Apple', url: 'https://bbs.kanxue.com/thread-273832.htm' }
    ]
  }
};

// Create flat list for backward compatibility
export const TECHNIQUES_LIST = Object.values(PWN_KNOWLEDGE_BASE);
