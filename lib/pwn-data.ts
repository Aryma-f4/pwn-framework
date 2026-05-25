export interface Technique {
  id: string;
  name: string;
  category: 'recon' | 'mitigation' | 'technique' | 'leaf' | 'setup';
  stack: string[];
  format: string[];
  heap: string[];
  sandbox: string[];
  description: string;
  prerequisites: string[];
  constraints: string[];
  blueprint: string;
  children?: string[];
}

export const PWN_TECHNIQUES: Record<string, Technique> = {
  root: {
    id: 'root',
    name: 'PWN Journey',
    category: 'root' as any,
    stack: [],
    format: [],
    heap: [],
    sandbox: [],
    description: 'The complete learning path for Binary Exploitation, from setup to advanced techniques',
    prerequisites: [],
    constraints: [],
    blueprint: 'journey.start();',
    children: ['setup_tools_root', 'prerequisites_root', 'tools_root', 'exploitation_root', 'mitigations_root', 'recon_tools_root'],
  },
  
  exploitation_root: {
    id: 'exploitation_root',
    name: 'PWN Exploitation Tree',
    category: 'root' as any,
    stack: [],
    format: [],
    heap: [],
    sandbox: [],
    description: 'Interactive decision tree for exploitation techniques across different vulnerability types',
    prerequisites: [],
    constraints: [],
    blueprint: 'framework.init() {\n  analyze_target();\n  identify_vulns();\n  develop_exploit();\n}',
    children: ['buffer_overflow', 'format_string', 'heap_exploit', 'sandbox_escape', 'fsop_exploit', 'integer_exploits'],
  },

  // MITIGATIONS BRANCH
  mitigations_root: {
    id: 'mitigations_root',
    name: 'Binary Protections',
    category: 'root',
    stack: [],
    format: [],
    heap: [],
    sandbox: [],
    description: 'Security features designed to prevent or mitigate exploitation of vulnerabilities',
    prerequisites: [],
    constraints: [],
    blueprint: 'analyze_mitigations() {\n  run("checksec --file=./binary");\n  identify_enabled_protections();\n  plan_bypasses();\n}',
    children: ['aslr_prot', 'nx_prot', 'canary_prot', 'relro_prot'],
  },

  aslr_prot: {
    id: 'aslr_prot',
    name: 'ASLR / PIE',
    category: 'mitigation',
    stack: [],
    format: [],
    heap: [],
    sandbox: [],
    description: 'Address Space Layout Randomization & Position Independent Executable randomizes memory segments',
    prerequisites: ['Kernel support', 'Compiler flags'],
    constraints: ['Must leak an address to bypass'],
    blueprint: 'aslr_defense() {\n  echo 2 > /proc/sys/kernel/randomize_va_space;\n  // gcc -pie -fPIE\n}',
    children: ['info_leak_bypass', 'partial_overwrite'],
  },

  info_leak_bypass: {
    id: 'info_leak_bypass',
    name: 'Information Leak',
    category: 'technique',
    stack: [],
    format: [],
    heap: [],
    sandbox: [],
    description: 'Leaking a pointer to calculate the base address of a randomized region',
    prerequisites: ['Out-of-bounds read or format string'],
    constraints: [],
    blueprint: 'bypass_aslr_leak() {\n  const leak = trigger_oob_read();\n  const libc_base = leak - offset_in_libc;\n  const system_addr = libc_base + system_offset;\n}',
    children: [],
  },

  partial_overwrite: {
    id: 'partial_overwrite',
    name: 'Partial Overwrite',
    category: 'technique',
    stack: [],
    format: [],
    heap: [],
    sandbox: [],
    description: 'Overwriting only the least significant bytes of a pointer to bypass ASLR without a leak',
    prerequisites: ['Little-endian architecture', 'Target on same page'],
    constraints: ['May require brute-forcing nibbles'],
    blueprint: 'partial_overwrite() {\n  // Overwrite the last 2 bytes of a pointer\n  // Need 1/16 luck if ASLR nibble is randomized\n  payload = p16(0x1234);\n  write_memory(target, payload);\n}',
    children: [],
  },

  nx_prot: {
    id: 'nx_prot',
    name: 'NX (No-Execute)',
    category: 'mitigation',
    stack: [],
    format: [],
    heap: [],
    sandbox: [],
    description: 'Marks memory regions (like the stack and heap) as non-executable to prevent shellcode execution',
    prerequisites: ['Hardware NX bit support'],
    constraints: ['Forces attacker to use code-reuse attacks'],
    blueprint: 'nx_defense() {\n  // Page tables mark stack/heap segments\n  // without the executable permission bit\n  // gcc -Wl,-z,noexecstack\n}',
    children: ['rop_bypass'],
  },

  rop_bypass: {
    id: 'rop_bypass',
    name: 'Code Reuse (ROP)',
    category: 'leaf',
    stack: [],
    format: [],
    heap: [],
    sandbox: [],
    description: 'Chaining existing executable code snippets to bypass NX',
    prerequisites: ['Known executable memory addresses'],
    constraints: [],
    blueprint: 'bypass_nx_rop() {\n  // Use tools like ROPgadget or ropper\n  chain = p64(pop_rdi) + p64(bin_sh) + p64(system);\n  send_payload(padding + chain);\n}',
    children: [],
  },

  canary_prot: {
    id: 'canary_prot',
    name: 'Stack Canaries',
    category: 'mitigation',
    stack: [],
    format: [],
    heap: [],
    sandbox: [],
    description: 'A random value placed before the saved return pointer to detect stack buffer overflows',
    prerequisites: ['Compiler flag (-fstack-protector)'],
    constraints: ['Must be leaked or bypassed to overwrite RIP'],
    blueprint: 'canary_defense() {\n  // gcc -fstack-protector-all\n  setup_canary() {\n    rax = fs:0x28;\n    [rbp-0x8] = rax;\n  }\n}',
    children: ['canary_leak', 'canary_bruteforce'],
  },

  canary_leak: {
    id: 'canary_leak',
    name: 'Canary Leak',
    category: 'leaf',
    stack: [],
    format: [],
    heap: [],
    sandbox: [],
    description: 'Reading the canary value using a format string or OOB read before returning',
    prerequisites: ['Read primitive'],
    constraints: [],
    blueprint: 'leak_canary() {\n  // %N$p where N is canary offset\n  canary = parse_hex(send_fmt_string("%15$p"));\n  payload = pad + p64(canary) + p64(0) + p64(rip);\n}',
    children: [],
  },

  canary_bruteforce: {
    id: 'canary_bruteforce',
    name: 'Canary Bruteforce',
    category: 'leaf',
    stack: [],
    format: [],
    heap: [],
    sandbox: [],
    description: 'Bruteforcing the canary byte-by-byte in forking servers',
    prerequisites: ['Forking network server'],
    constraints: ['Server must not crash the main process on bad canary'],
    blueprint: 'brute_canary() {\n  canary = "\\x00";\n  for (let i = 1; i < 8; i++) {\n    for (let b = 0; b < 256; b++) {\n      if (test_byte(canary + chr(b))) canary += chr(b);\n    }\n  }\n}',
    children: [],
  },

  relro_prot: {
    id: 'relro_prot',
    name: 'RELRO',
    category: 'mitigation',
    stack: [],
    format: [],
    heap: [],
    sandbox: [],
    description: 'Relocation Read-Only hardens ELF programs against GOT overwrites',
    prerequisites: ['Compiler flags (-z relro, -z now)'],
    constraints: ['Full RELRO makes GOT read-only'],
    blueprint: 'relro_defense() {\n  // Full RELRO: gcc -Wl,-z,relro,-z,now\n  // Partial RELRO: gcc -Wl,-z,relro,-z,lazy\n}',
    children: ['relro_bypass'],
  },

  relro_bypass: {
    id: 'relro_bypass',
    name: 'Hook Overwrite / FSOP',
    category: 'leaf',
    stack: [],
    format: [],
    heap: [],
    sandbox: [],
    description: 'Bypassing Full RELRO by targeting writable function pointers elsewhere (e.g. __free_hook, _IO_FILE vtables)',
    prerequisites: ['Arbitrary write primitive'],
    constraints: [],
    blueprint: 'bypass_relro() {\n  // Target __free_hook instead of GOT\n  free_hook_addr = libc_base + free_hook_offset;\n  arbitrary_write(free_hook_addr, system_addr);\n  free(ptr_to_bin_sh);\n}',
    children: [],
  },

  // RECONNAISSANCE BRANCH
  recon_tools_root: {
    id: 'recon_tools_root',
    name: 'Reconnaissance Methodology',
    category: 'root',
    stack: [],
    format: [],
    heap: [],
    sandbox: [],
    description: 'The critical first step of exploitation: analyzing the binary to find vulnerabilities and constraints',
    prerequisites: [],
    constraints: [],
    blueprint: `RECONNAISSANCE & TRIAGE WORKFLOW
================================

Phase 1: Binary Identification
------------------------------
$ file ./target
  # Look for: 32-bit vs 64-bit, LSB/MSB, dynamically vs statically linked, and stripped vs not stripped.
  # If stripped, you will lack function names in debuggers/decompilers.

Phase 2: Security Mitigations (checksec)
----------------------------------------
$ checksec --file=./target
  # NX (No-eXecute): If enabled, you cannot execute shellcode on the stack. You must use ROP.
  # PIE (Position Independent Executable): If enabled, binary addresses are randomized. You need an info leak to find the base address.
  # Canary: If enabled, buffer overflows will crash before returning. You must leak the canary or bypass it.
  # RELRO (Relocation Read-Only): If Full, GOT overwrite is impossible. If Partial, GOT overwrite is allowed.

Phase 3: Basic Execution & Behavioral Testing
-------------------------------------------
1. Run normally: $ ./target
2. Fuzz input length: Input 500 'A's. Does it segfault?
3. Fuzz format strings: Input '%p %p %p %p' or '%x-%x'. Does it leak memory addresses?
4. Integer edge cases: Input negative numbers (-1) or large numbers (4294967295).

Phase 4: Environment Replication
------------------------------
If given a libc.so.6 and ld-linux.so:
$ pwninit --bin ./target --libc ./libc.so.6 --ld ./ld.so
$ patchelf --set-interpreter ./ld.so --set-rpath ./ ./target
  # This ensures your local offsets perfectly match the remote CTF server!`,
    children: ['static_analysis', 'dynamic_analysis'],
  },

  static_analysis: {
    id: 'static_analysis',
    name: 'Static Analysis',
    category: 'recon',
    stack: [],
    format: [],
    heap: [],
    sandbox: [],
    description: 'Analyzing the binary without executing it (disassembly, decompilation, structure analysis)',
    prerequisites: ['Binary file access'],
    constraints: ['Obfuscation/packing can hinder analysis'],
    blueprint: `STATIC ANALYSIS (GHIDRA / IDA / RADARE2)
========================================

Phase 1: Deep String & Symbol Analysis
--------------------------------------
$ strings -n 8 ./target | grep -i "flag\\|sh\\|bin\\|system"
  # Search for backdoor functions or hardcoded secrets.
$ readelf -s ./target
  # List all symbols. Look for suspicious functions like 'win', 'give_shell', 'debug'.
$ objdump -M intel -d ./target | less
  # Quick CLI disassembly (Intel syntax).

Phase 2: Decompilation (Ghidra/IDA)
-----------------------------------
1. Import binary and let the auto-analysis run.
2. If the binary is stripped, start at the 'entry' point (usually _start), find the first argument passed to __libc_start_main, which is main().
3. Rename the function to 'main'.
4. Rename all local variables (e.g., local_10 -> buffer, local_14 -> counter).
5. Retype variables (e.g., change 'undefined4' to 'int', 'undefined8*' to 'char*').

Phase 3: Vulnerability Hunting
------------------------------
- Stack Overflows: Look for gets(buf), scanf("%s", buf), strcpy(buf, input), or read(0, buf, size) where size > buf_size.
- Format Strings: Look for printf(buf) instead of printf("%s", buf).
- Off-by-ones: Look for loops like \`for(int i=0; i <= size; i++)\` (<= instead of <).
- Type confusions: Look for \`int size = read(); if (size < 10)\`, but size is signed and can be negative, bypassing the check but wrapping to a huge number in memcpy/read.`,
    children: [],
  },

  dynamic_analysis: {
    id: 'dynamic_analysis',
    name: 'Dynamic Analysis',
    category: 'recon',
    stack: [],
    format: [],
    heap: [],
    sandbox: [],
    description: 'Observing the binary\'s behavior during execution (debugging, tracing)',
    prerequisites: ['Execution environment', 'Debugger'],
    constraints: ['Anti-debugging techniques'],
    blueprint: `DYNAMIC ANALYSIS & DEBUGGING (GDB/PWNDBG)
=========================================

Phase 1: Dynamic Tracing
------------------------
$ strace -i -v ./target
  # See exactly what system calls the binary executes (open, read, execve, mmap).
$ ltrace ./target
  # See what library functions are called and with what arguments (e.g., strcmp, malloc, puts).

Phase 2: GDB Setup & Breakpoints
--------------------------------
$ gdb ./target
gdb> break main
gdb> break *main+142    # Break at a specific instruction offset (useful if stripped)
gdb> run                # Start execution
gdb> continue           # Continue after breakpoint

Phase 3: Analyzing State (Pwndbg/GEF)
-------------------------------------
gdb> context            # Print registers, disasm, and stack view
gdb> x/40wx $rsp        # Examine 40 words (hex) at the stack pointer
gdb> x/10gx $rbp-0x20   # Examine 10 giant words at a specific offset
gdb> vmmap              # View memory permissions (look for 'rwx' or libc base)
gdb> search -p "/bin/sh"# Search memory for the "/bin/sh" string
gdb> info frame         # View current stack frame details (saved RIP, RBP)

Phase 4: Crash Analysis & Offset Finding
----------------------------------------
gdb> cyclic 200         # Generate a cyclic pattern of 200 bytes
gdb> run                # Paste the pattern when prompted for input
# Binary crashes (SIGSEGV). Look at the instruction pointer (RIP) or stack pointer (RSP).
gdb> cyclic -l $rsp     # If RSP points to pattern 'jaaa', this command outputs the exact padding offset!

Phase 5: Exploitation Setup (Pwntools)
--------------------------------------
# In your exploit.py:
gdb.attach(p, '''
break main
continue
''')`,
    children: [],
  },

  // BUFFER OVERFLOW BRANCH
  buffer_overflow: {
    id: 'buffer_overflow',
    name: 'Buffer Overflow',
    category: 'recon',
    stack: ['stack-based'],
    format: [],
    heap: [],
    sandbox: [],
    description: 'Exploits by overwriting stack buffers to redirect execution flow',
    prerequisites: ['No ASLR', 'No Stack Canaries', 'Vulnerable input handling'],
    constraints: ['Requires buffer size knowledge', 'Address space must be predictable'],
    blueprint: 'buffer_overflow_exploit() {\n  const payload = craft_rop_chain();\n  trigger_vulnerable_function(payload);\n  hijack_execution_flow();\n}',
    children: ['stack_pivot', 'rop_chain', 'ret2csu', 'ret2dlresolve', 'srop', 'stack_clash', 'brop', 'jop', 'ret2vdso'],
  },

  brop: {
    id: 'brop',
    name: 'Blind ROP (BROP)',
    category: 'technique',
    stack: ['stack-based'],
    format: [],
    heap: [],
    sandbox: [],
    description: 'Bypassing ASLR/NX remotely without the binary by brute-forcing gadgets byte-by-byte. Works on forking servers where crashes are non-fatal and the binary image is shared.',
    prerequisites: ['Server that forks on connection (crash-tolerant)', 'No PIE (or brute-forceable PIE)', 'NX enabled', 'No stack canary'],
    constraints: ['Requires 1000-10000+ requests depending on address space', 'Server must stay up after child crash'],
    blueprint: `BROP WORKFLOW
=====
1. Find overflow offset (send increasing lengths until crash)
2. Find Stop Gadget (probe addresses — valid ret/addrs don't crash)
3. Find BROP Gadget (pop rdi; ret — probe stop+gadget pairs)
4. Find puts@plt (pop_rdi + got_entry + candidate_plt)
5. Dump .text section via puts@plt
6. Identify libc version from leaked pointers
7. Build final ROP chain`,
    children: ['rop_exec'],
  },

  jop: {
    id: 'jop',
    name: 'Jump Oriented Programming (JOP)',
    category: 'technique',
    stack: ['stack-based'],
    format: [],
    heap: [],
    sandbox: [],
    description: 'Code reuse attack using indirect jumps (jmp [reg]) instead of ret instructions. Bypasses shadow stacks (Intel CET) and return-address-based defenses since no rets are used.',
    prerequisites: ['Dispatcher gadget (e.g., jmp [rax] or call [rbx])', 'Control over the dispatch register', 'Predictable jump tables or indirect call targets'],
    constraints: ['Finding a suitable dispatcher loop is very difficult', 'Gadgets must end with indirect jump, not ret', 'Requires per-binary gadget discovery — not generic'],
    blueprint: 'jop() {\n  // Find: add rax, 8; jmp [rax]  (dispatcher)\n  // Place gadget addresses in a "dispatch table"\n  setup_dispatch_table(functional_gadgets);\n  set_dispatch_register(dispatch_table);\n  chain: load → store → syscall via jump dispatches\n}',
    children: ['rop_exec'],
  },

  ret2vdso: {
    id: 'ret2vdso',
    name: 'ret2vdso',
    category: 'technique',
    stack: ['stack-based'],
    format: [],
    heap: [],
    sandbox: [],
    description: 'Leverages the kernel-provided vDSO (virtual dynamic shared object) mapped into every process to call syscalls directly (like rt_sigreturn, gettimeofday). The vDSO contains syscall/sysenter trampolines at randomized but contiguous addresses.',
    prerequisites: ['vDSO mapped (always present on Linux)', 'Leak of vDSO base (or use partial overwrite if PIE off)'],
    constraints: ['vDSO is randomized with ASLR', 'Only contains syscall entry stubs, not general gadgets'],
    blueprint: `ret2vdso() {
  // vDSO contains:
  // __kernel_vsyscall  →  sysenter / syscall
  // __kernel_sigreturn →  rt_sigreturn
  // __kernel_rt_sigreturn → rt_sigreturn
  leak_vdso_base();
  // If PIE is off, vDSO base can be partially overwritten
  vdso_sigreturn = vdso_base + sigreturn_offset;
  // Chain to SROP via vDSO sigreturn trampoline
}`,
    children: ['srop'],
  },

  stack_pivot: {
    id: 'stack_pivot',
    name: 'Stack Pivot',
    category: 'technique',
    stack: ['stack-based'],
    format: [],
    heap: [],
    sandbox: [],
    description: 'Redirects RSP from the real stack to an attacker-controlled region (heap, BSS, libc data). Critical when overflow space past RIP is too small for a full ROP chain. Common gadgets: leave;ret, xchg rsp,rax;ret, pop rsp;ret.',
    prerequisites: ['ROP gadgets available', 'Writable memory region at known address for fake stack'],
    constraints: ['Must know a writable address for the new stack', 'Fake stack must be pre-populated with the secondary ROP chain'],
    blueprint: `stack_pivot_via_leave_ret() {
  // Place secondary ROP chain at writable_addr
  pre_write_chain(writable_addr, secondary_rop);

  // Primary overflow (small):
  payload = 'A' * rbp_offset;
  payload += p64(fake_rbp);  // writable_addr - 8
  payload += p64(leave_ret); // mov rsp,rbp; pop rbp; ret
  
  // On ret: RSP → fake_rbp+8 → secondary chain begins
}`,
    children: ['rop_exec', 'heap_spray'],
  },

  rop_chain: {
    id: 'rop_chain',
    name: 'ROP Chain',
    category: 'technique',
    stack: ['stack-based'],
    format: [],
    heap: [],
    sandbox: [],
    description: 'Links return-oriented programming gadgets to execute arbitrary code',
    prerequisites: ['Gadget finder output', 'Binary analysis'],
    constraints: ['Gadget availability', 'Instruction alignment'],
    blueprint: 'rop_exploit() {\n  const gadgets = find_gadgets(binary);\n  const chain = build_chain(gadgets, payload);\n  execute_chain(chain);\n}',
    children: ['rop_exec'],
  },

  rop_exec: {
    id: 'rop_exec',
    name: 'ROP Execution',
    category: 'leaf',
    stack: ['stack-based'],
    format: [],
    heap: [],
    sandbox: [],
    description: 'Final execution stage using ROP gadgets to call system functions',
    prerequisites: ['Complete ROP chain', 'Target function addressable'],
    constraints: ['Call convention compliance', 'Register state'],
    blueprint: 'exec_rop() {\n  // Load system() address\n  mov rdi, "/bin/sh";\n  call system_addr;\n  // Execute shell\n}',
    children: [],
  },

  ret2csu: {
    id: 'ret2csu',
    name: 'Ret2csu',
    category: 'technique',
    stack: ['stack-based'],
    format: [],
    heap: [],
    sandbox: [],
    description: 'Uses gadgets from __libc_csu_init to populate rdx, rsi, rdi and call functions',
    prerequisites: ['x64 dynamically linked binary', '__libc_csu_init present'],
    constraints: ['Needs specific gadget layout from glibc'],
    blueprint: 'ret2csu() {\n  call csu_gadget_1;\n  call csu_gadget_2;\n}',
    children: ['rop_exec'],
  },

  ret2dlresolve: {
    id: 'ret2dlresolve',
    name: 'Ret2dl-resolve',
    category: 'technique',
    stack: ['stack-based'],
    format: [],
    heap: [],
    sandbox: [],
    description: 'Forces the dynamic linker to resolve an arbitrary function (like system) instead of a legit one',
    prerequisites: ['No RELRO or Partial RELRO', 'No PIE (typically)', 'Large buffer space'],
    constraints: ['Complex payload setup'],
    blueprint: 'ret2dl() {\n  fake_reloc();\n  fake_symtab();\n  call_dl_resolve();\n}',
    children: ['rop_exec'],
  },

  srop: {
    id: 'srop',
    name: 'SROP (Sigreturn)',
    category: 'technique',
    stack: ['stack-based'],
    format: [],
    heap: [],
    sandbox: [],
    description: 'Sigreturn Oriented Programming — forges a signal frame (SigreturnFrame) on the stack. When the kernel\'s rt_sigreturn syscall restores it, all 15 x86_64 registers are set to attacker-controlled values in a single step. The "one-shot" of ROP.',
    prerequisites: ['Control over RAX (set to 15 for sigreturn)', '"syscall; ret" gadget', 'Large stack buffer (~0x178+ bytes)'],
    constraints: ['Requires ~376 bytes of overflow space on x86_64', 'rt_sigreturn (syscall 15) must not be blocked by seccomp'],
    blueprint: `srop_one_shot() {
  frame = SigreturnFrame()
  frame.rax = 59           // SYS_execve
  frame.rdi = &"/bin/sh"   // filename
  frame.rsi = 0            // argv
  frame.rdx = 0            // envp
  frame.rip = syscall_gadget

  payload = padding + pop_rax(15) + syscall_gadget + bytes(frame)
  // → sigreturn restores frame → execve("/bin/sh") runs
}`,
    children: ['rop_exec'],
  },

  stack_clash: {
    id: 'stack_clash',
    name: 'Stack Clash',
    category: 'technique',
    stack: ['stack-based'],
    format: [],
    heap: [],
    sandbox: [],
    description: 'Jumps over the stack guard page by allocating a very large stack variable or using alloca(), causing the stack to grow into another memory region (heap, mmap, or another thread\'s stack). Enables cross-region memory corruption without a typical overflow.',
    prerequisites: ['Large stack allocation capability', 'VLA or alloca() with attacker-controlled size', 'Kernel without guard-gap protection (< 4.13)'],
    constraints: ['OS/Kernel patch specific', 'Modern kernels have stack clash protection'],
    blueprint: `stack_clash_exploit() {
  // Allocate a huge stack frame to jump the guard page
  alloca(0x200000);  // Allocates 2MB, skipping guard
  
  // Stack pointer now overlaps with heap or another region
  // Write through stack touches another thread's memory
  
  // Modern: requires CVE-2017-1000364 style exploitation
}`,
    children: [],
  },

  heap_spray: {
    id: 'heap_spray',
    name: 'Heap Spray',
    category: 'leaf',
    stack: [],
    format: [],
    heap: ['heap-based'],
    sandbox: [],
    description: 'Allocates massive heap objects to occupy predictable memory addresses',
    prerequisites: ['Heap allocator control', 'Large memory available'],
    constraints: ['Memory pressure limits', 'Allocator implementation knowledge'],
    blueprint: 'spray_heap() {\n  for (let i = 0; i < 0x10000; i++) {\n    allocate(SPRAY_SIZE);\n  }\n}',
    children: [],
  },

  // FORMAT STRING BRANCH
  format_string: {
    id: 'format_string',
    name: 'Format String',
    category: 'recon',
    stack: [],
    format: ['format-string'],
    heap: [],
    sandbox: [],
    description: 'Exploits unvalidated printf-style format strings to leak/write memory',
    prerequisites: ['Unvalidated user input', 'Format function usage'],
    constraints: ['Format string position discovery', 'Address alignment'],
    blueprint: 'format_string_exploit() {\n  const offset = discover_offset();\n  const payload = "%x".repeat(offset) + "%n";\n  leak_memory(payload);\n}',
    children: ['format_leak', 'format_write', 'blind_format', 'stack_chk_fail_hijack'],
  },

  format_leak: {
    id: 'format_leak',
    name: 'Memory Leak via %x',
    category: 'technique',
    stack: [],
    format: ['format-string'],
    heap: [],
    sandbox: [],
    description: 'Reads stack/memory values using format string read specifiers',
    prerequisites: ['Format string position known'],
    constraints: ['Offset precision required'],
    blueprint: 'leak_via_format() {\n  const payload = "%p %p %p %p";\n  return format_function(payload);\n}',
    children: ['leak_libc', 'leak_stack'],
  },

  format_write: {
    id: 'format_write',
    name: 'Memory Write via %n',
    category: 'technique',
    stack: [],
    format: ['format-string'],
    heap: [],
    sandbox: [],
    description: 'Writes arbitrary values to memory using %n specifier',
    prerequisites: ['Target address known', 'Format position known'],
    constraints: ['Alignment requirements', 'Byte-by-byte writing needed'],
    blueprint: 'write_via_format() {\n  const target = get_got_entry();\n  const payload = build_format_write(target, value);\n  format_function(payload);\n}',
    children: ['got_overwrite'],
  },

  leak_libc: {
    id: 'leak_libc',
    name: 'Leak libc Address',
    category: 'leaf',
    stack: [],
    format: ['format-string'],
    heap: [],
    sandbox: [],
    description: 'Extracts libc base address for ASLR bypass',
    prerequisites: ['libc symbol addressable', 'Format position discovered'],
    constraints: ['Predictable libc offset', 'Symbol must be on stack'],
    blueprint: 'leak_libc_addr() {\n  const payload = craft_leak_payload();\n  const leaked = format_function(payload);\n  return subtract_offset(leaked, LIBC_OFFSET);\n}',
    children: [],
  },

  leak_stack: {
    id: 'leak_stack',
    name: 'Leak Stack Values',
    category: 'leaf',
    stack: [],
    format: ['format-string'],
    heap: [],
    sandbox: [],
    description: 'Reads values directly from the stack for information disclosure',
    prerequisites: ['Stack layout known'],
    constraints: ['Address range limitations'],
    blueprint: 'leak_stack() {\n  const payload = "%x ".repeat(20);\n  return format_function(payload);\n}',
    children: [],
  },

  got_overwrite: {
    id: 'got_overwrite',
    name: 'GOT Overwrite',
    category: 'leaf',
    stack: [],
    format: ['format-string'],
    heap: [],
    sandbox: [],
    description: 'Overwrites Global Offset Table entries to hijack function calls',
    prerequisites: ['Target GOT address known', '%n capability'],
    constraints: ['Got entry must be writable'],
    blueprint: 'overwrite_got() {\n  const got_addr = find_got_entry(target_func);\n  const payload = write_payload(got_addr, shell_addr);\n  format_function(payload);\n}',
    children: [],
  },

  stack_chk_fail_hijack: {
    id: 'stack_chk_fail_hijack',
    name: '__stack_chk_fail Hijack',
    category: 'leaf',
    stack: [],
    format: ['format-string'],
    heap: [],
    sandbox: [],
    description: 'Overwriting the GOT entry of __stack_chk_fail so that triggering a stack smash executes arbitrary code instead of aborting.',
    prerequisites: ['Format string write primitive', 'Stack canary enabled'],
    constraints: ['Partial RELRO only'],
    blueprint: 'hijack_chk_fail() {\n  fmt_overwrite(got_stack_chk_fail, system);\n  trigger_stack_smash();\n}',
    children: [],
  },

  blind_format: {
    id: 'blind_format',
    name: 'Blind Format String',
    category: 'technique',
    stack: [],
    format: ['format-string'],
    heap: [],
    sandbox: [],
    description: 'Format string vulnerability where output is not echoed back to the attacker (e.g., written to a log file or pipe that is not read). Must use side channels (crash/no-crash, timing delays) to infer leaked data or confirm writes.',
    prerequisites: ['Vulnerability exists but output is suppressed/redirected', 'Observable side channel: crash, timing, or indirect output'],
    constraints: ['Significantly slower exploitation (~seconds per byte)', 'Requires forking server or multi-connection tolerance'],
    blueprint: `blind_fsb_exploit() {
  // Crash oracle: overwrite GOT entry byte-by-byte
  for (addr in target_range) {
    // Overwrite 1 byte with %hhn → if crash, wrong byte
    send_fmt("AAAA" + "%N$hhn")  
    if (!crashed) byte_found();
  }
  
  // Timing oracle: measure response delay for leaked bits
  // Conditional: if bit is 1, call sleep(1)
  // Then measure response time → infer bit value
}`,
    children: [],
  },

  // HEAP EXPLOIT BRANCH
  heap_exploit: {
    id: 'heap_exploit',
    name: 'Heap Exploit',
    category: 'recon',
    stack: [],
    format: [],
    heap: ['heap-based'],
    sandbox: [],
    description: 'Exploits heap metadata and allocator behavior for code execution',
    prerequisites: ['Heap overflow', 'Allocator implementation knowledge'],
    constraints: ['Heap layout control', 'Metadata accessible'],
    blueprint: 'heap_exploit() {\n  corrupt_heap_metadata();\n  trigger_allocator_vuln();\n  achieve_code_exec();\n}',
    children: ['use_after_free', 'double_free', 'house_of_botcake', 'house_of_rabbit', 'house_of_roman', 'house_of_lore', 'tcache_stashing', 'house_of_force', 'house_of_spirit', 'house_of_einherjar', 'unsorted_bin_attack', 'large_bin_attack', 'first_fit', 'poison_null_byte', 'house_of_husk', 'house_of_corrosion', 'house_of_apple', 'house_of_cat', 'overlapping_chunks', 'signal_handler_exploit', 'house_of_banana', 'house_of_emma', 'house_of_blaze', 'house_of_fun', 'house_of_error', 'house_of_blind', 'house_of_crane', 'house_of_atum', 'house_of_kiwi', 'house_of_card'],
  },

  use_after_free: {
    id: 'use_after_free',
    name: 'Use-After-Free',
    category: 'technique',
    stack: [],
    format: [],
    heap: ['heap-based'],
    sandbox: [],
    description: 'A memory pointer is used after the memory it points to has been freed. The attacker reallocates a same-size object into the freed slot, causing the dangling pointer to operate on attacker-controlled data (type confusion / vtable hijack).',
    prerequisites: ['free(p) called without p = NULL', 'Later code dereferences p', 'Ability to allocate controlled data in the freed slot'],
    constraints: ['Allocation must be of same size class for heap reuse', 'Timing between free and use is critical'],
    blueprint: `uaf_exploit() {
  obj = allocate(0x50);       // allocate an object
  free(obj);                  // free it (dangling ptr!)
  
  // Reallocate attacker-controlled same-size object
  fake = allocate(0x50);
  *(uint64_t*)fake = target;  // overwrite old vtable/buffer
  
  obj->method();  // UAF: uses dangling obj → calls fake vtable!
}`,
    children: ['heap_spray', 'vtable_hijack'],
  },

  double_free: {
    id: 'double_free',
    name: 'Double Free',
    category: 'technique',
    stack: [],
    format: [],
    heap: ['heap-based'],
    sandbox: [],
    description: 'Frees the same memory twice to corrupt heap state',
    prerequisites: ['Control over free calls', 'Allocator checks disabled'],
    constraints: ['Ptmalloc/jemalloc specific', 'Glibc version dependent'],
    blueprint: 'double_free() {\n  const ptr = allocate();\n  free(ptr);\n  free(ptr);  // Double free\n  reallocate_for_control();\n}',
    children: ['heap_control'],
  },

  vtable_hijack: {
    id: 'vtable_hijack',
    name: 'VTable Hijack',
    category: 'leaf',
    stack: [],
    format: [],
    heap: ['heap-based'],
    sandbox: [],
    description: 'Corrupts C++ vtable pointers to redirect virtual function calls',
    prerequisites: ['C++ object vulnerability', 'Heap write primitive'],
    constraints: ['VTable addressable', 'Method called after corruption'],
    blueprint: 'hijack_vtable() {\n  const obj = get_vulnerable_object();\n  obj.vtable = fake_vtable_addr;\n  obj.virtual_method();  // Redirected\n}',
    children: [],
  },

  heap_control: {
    id: 'heap_control',
    name: 'Heap Control',
    category: 'leaf',
    stack: [],
    format: [],
    heap: ['heap-based'],
    sandbox: [],
    description: 'Achieves arbitrary allocation control for object placement',
    prerequisites: ['Heap corruption', 'Allocator state manipulation'],
    constraints: ['Size class alignment', 'Bin management knowledge'],
    blueprint: 'control_heap() {\n  corrupt_heap_bins();\n  allocate_target_size();\n  return get_predictable_chunk();\n}',
    children: [],
  },

  house_of_force: {
    id: 'house_of_force',
    name: 'House of Force',
    category: 'technique',
    stack: [],
    format: [],
    heap: ['heap-based'],
    sandbox: [],
    description: 'Overwriting the Top Chunk (wilderness) size to -1, enabling massive mallocs that wrap around the address space to return a pointer anywhere in memory.',
    prerequisites: ['Heap overflow', 'Glibc < 2.29'],
    constraints: ['Target address must be at a higher address than heap base'],
    blueprint: 'force() {\n  overwrite_top_chunk_size(-1);\n  malloc(target - top_chunk - 0x20);\n  malloc(0x10); // Returns target ptr\n}',
    children: ['heap_control'],
  },

  house_of_spirit: {
    id: 'house_of_spirit',
    name: 'House of Spirit',
    category: 'technique',
    stack: [],
    format: [],
    heap: ['heap-based'],
    sandbox: [],
    description: 'Forging a fake chunk structure on the stack (or .bss) and passing its address to free(), putting the stack pointer into the fastbin.',
    prerequisites: ['Ability to call free() on arbitrary address', 'Stack/BSS write access'],
    constraints: ['Must forge valid chunk size and next chunk size'],
    blueprint: 'spirit() {\n  forge_chunk_on_stack(0x40, 0x1234);\n  free(stack_ptr);\n  malloc(0x30); // Returns stack ptr\n}',
    children: ['heap_control'],
  },

  house_of_einherjar: {
    id: 'house_of_einherjar',
    name: 'House of Einherjar',
    category: 'technique',
    stack: [],
    format: [],
    heap: ['heap-based'],
    sandbox: [],
    description: 'A single-byte overflow (off-by-one) sets the PREV_INUSE bit of the next chunk to 0, forcing backward consolidation with a fake chunk to overlap memory.',
    prerequisites: ['Off-by-one NULL byte overflow', 'Heap leak'],
    constraints: ['Complex fake chunk setup (fd/bk pointers)'],
    blueprint: 'einherjar() {\n  forge_fake_chunk_in_heap();\n  off_by_one_null_byte();\n  free(next_chunk); // Consolidates backward\n}',
    children: ['heap_control'],
  },

  unsorted_bin_attack: {
    id: 'unsorted_bin_attack',
    name: 'Unsorted Bin Attack',
    category: 'technique',
    stack: [],
    format: [],
    heap: ['heap-based'],
    sandbox: [],
    description: 'Corrupting the bk pointer of an unsorted bin chunk to write a large libc pointer (main_arena+88) to an arbitrary memory location.',
    prerequisites: ['UAF or Overflow on unsorted bin chunk'],
    constraints: ['Only writes a fixed libc address, cannot control the value'],
    blueprint: 'unsorted_attack() {\n  chunk->bk = target_addr - 0x10;\n  malloc(0); // Unlinks and writes libc ptr to target\n}',
    children: ['heap_control'],
  },

  large_bin_attack: {
    id: 'large_bin_attack',
    name: 'Large Bin Attack',
    category: 'technique',
    stack: [],
    format: [],
    heap: ['heap-based'],
    sandbox: [],
    description: 'Corrupting the fd_nextsize or bk_nextsize of a large bin chunk to achieve an arbitrary write when chunks are sorted/inserted into the large bin.',
    prerequisites: ['Ability to allocate large chunks (>0x400)', 'Heap vulnerability'],
    constraints: ['Writes a heap pointer, not an arbitrary value'],
    blueprint: 'large_bin() {\n  corrupt_bk_nextsize(target - 0x20);\n  malloc(large_size); // Triggers insertion and write\n}',
    children: ['heap_control'],
  },

  house_of_botcake: {
    id: 'house_of_botcake',
    name: 'House of Botcake',
    category: 'technique',
    stack: [],
    format: [],
    heap: ['heap-based'],
    sandbox: [],
    description: 'Bypasses tcache double-free checks by consolidating a large chunk, then freeing a smaller enclosed chunk to tcache',
    prerequisites: ['Glibc 2.29-2.31+', 'Ability to allocate and free 7 chunks (fill tcache)'],
    constraints: ['Needs overlapping chunks capability'],
    blueprint: 'botcake() {\n  fill_tcache();\n  free(prev); free(target); // consolidate\n  free(target); // to tcache\n}',
    children: ['heap_control'],
  },

  house_of_rabbit: {
    id: 'house_of_rabbit',
    name: 'House of Rabbit',
    category: 'technique',
    stack: [],
    format: [],
    heap: ['heap-based'],
    sandbox: [],
    description: 'Exploits malloc_consolidate to link fake chunks into fastbins and bypass checks',
    prerequisites: ['Large allocation capability', 'Heap info leak'],
    constraints: ['Very precise size formatting needed'],
    blueprint: 'rabbit() {\n  trigger_malloc_consolidate();\n  forge_fastbin();\n}',
    children: ['heap_control'],
  },

  house_of_roman: {
    id: 'house_of_roman',
    name: 'House of Roman',
    category: 'technique',
    stack: [],
    format: [],
    heap: ['heap-based'],
    sandbox: [],
    description: 'ASLR bypass for fastbin double free/unsorted bin attack using partial byte overwrites without leaks',
    prerequisites: ['Heap vulnerability (UAF/overflow)', 'No libc leak needed'],
    constraints: ['Requires 12-bit brute force (1/4096 success rate)'],
    blueprint: 'roman() {\n  overwrite_lsb_fd();\n  unsorted_bin_attack_lsb();\n}',
    children: ['heap_control'],
  },

  house_of_lore: {
    id: 'house_of_lore',
    name: 'House of Lore',
    category: 'technique',
    stack: [],
    format: [],
    heap: ['heap-based'],
    sandbox: [],
    description: 'Corrupts the smallbin free list by manipulating the bk pointer of a freed chunk, causing malloc to return an arbitrary address. The attacker forges a fake chunk in the target region and links it into the smallbin via bk pointer corruption.',
    prerequisites: ['Ability to corrupt a smallbin chunk bk pointer', 'Smallbin must have chunks (not all in fastbin/tcache)', 'Fake chunk must have valid size field at fake+8'],
    constraints: ['Requires smallbin to be used (chunks > fastbin size)', 'Glibc < 2.29 has fewer checks on smallbin', 'Glibc 2.29+ validates victim->bk->fd == victim'],
    blueprint: `house_of_lore() {
  // Step 1: Ensure victim is in smallbin
  free(large_chunk);  // Goes to unsorted bin, then smallbin
  
  // Step 2: Corrupt victim->bk to point to fake chunk
  victim->bk = &fake_chunk - 0x10;  // fake_chunk->fd must point to victim
  
  // Step 3: malloc() walks smallbin, finds victim
  //          then victim->bk->fd == victim (check passes!)
  //          Returns fake_chunk address
  ptr = malloc(size);  // Returns fake_chunk address!
}`,
    children: ['heap_control'],
  },

  overlapping_chunks: {
    id: 'overlapping_chunks',
    name: 'Overlapping Chunks',
    category: 'technique',
    stack: [],
    format: [],
    heap: ['heap-based'],
    sandbox: [],
    description: 'Corrupts chunk metadata (size field) so two malloc allocations overlap the same memory region. Enables reading/writing data from one allocation through another — powerful for tcache poisoning, libc leaks, and arbitrary writes.',
    prerequisites: ['Heap overflow to corrupt a chunk size field', 'Ability to allocate/free chunks before and after the corruption'],
    constraints: ['Must satisfy size alignment checks (0x10-aligned)', 'Next chunk prev_size must be consistent for free()', 'Glibc 2.29+ adds more validation checks'],
    blueprint: `overlapping_chunks() {
  // Step 1: Allocate A, B, C (adjacent)
  A = malloc(0x18); B = malloc(0x18); C = malloc(0x18);
  
  // Step 2: Overflow A into B's size field
  B->size = 0x41;  // Enlarge B to encompass C
  
  // Step 3: Free B — adds to fastbin/tcache as size 0x40
  free(B);
  
  // Step 4: malloc(0x30) returns B region
  // But C is still alive inside B's range!
  // Read/Write through C overlaps with B's new allocation
  D = malloc(0x30);  // D == B's address, overlaps C
}`,
    children: ['heap_control'],
  },

  signal_handler_exploit: {
    id: 'signal_handler_exploit',
    name: 'Signal Handler Exploitation',
    category: 'technique',
    stack: ['stack-based'],
    format: [],
    heap: [],
    sandbox: [],
    description: 'Abusing signal handlers (SIGALRM, SIGSEGV, etc.) that execute user-controllable code in an async context. Common in CTF: alarm() triggers SIGALRM handler that prints data, or a crash handler that leaks memory — enabling info disclosure or even code execution.',
    prerequisites: ['Binary installs a signal handler (signal() / sigaction())', 'Handler uses global/heap data that attacker can influence'],
    constraints: ['Handler must be reachable', 'Race conditions may limit reliability'],
    blueprint: `signal_handler_exploit() {
  // Common CTF patterns:
  // 1. alarm(1) + SIGALRM handler prints flag → just wait
  // 2. SIGSEGV handler that calls puts(ptr) → leak via crash
  // 3. Handler calls free(global) + UAF later → race window
  // 4. Handler calls write(1, buf, len) with attacker-controlled buf/len
  
  // Exploit: trigger signal, then corrupt data handler reads
  signal(SIGALRM, handler);
  alarm(1);
  while(1) { corrupt_shared_data(); }
}`,
    children: [],
  },

  tcache_stashing: {
    id: 'tcache_stashing',
    name: 'Tcache Stashing Unlink',
    category: 'technique',
    stack: [],
    format: [],
    heap: ['heap-based'],
    sandbox: [],
    description: 'Exploits calloc()\'s behavior: calloc bypasses tcache and picks from smallbins, then "stashes" remaining smallbin chunks into tcache. By corrupting a smallbin chunk\'s bk pointer, this stashing unlink can write a libc pointer to an arbitrary address.',
    prerequisites: ['calloc() usage (NOT malloc)', 'Glibc 2.26-2.31', 'Ability to corrupt smallbin bk pointer', 'tcache not full (1-6 entries)'],
    constraints: ['calloc must be used — malloc goes to tcache first', 'Requires specific smallbin/tcache layout'],
    blueprint: `tcache_stashing_unlink() {
  // Setup: free chunks to create smallbin + partial tcache
  fill_tcache_partially(5);    // leave some slots empty
  free(a); free(b);             // a → unsorted → smallbin (after next malloc)
  // ... consolidate properly
  
  // Corrupt last smallbin chunk's bk
  smallbin_tail->bk = target_addr - 0x10;
  
  // Trigger: calloc(size) → stashes into tcache → 
  // target_addr receives libc pointer (main_arena+X)
  c = calloc(1, size);  // BOOM: arbitrary write
}`,
    children: ['heap_control'],
  },

  first_fit: {
    id: 'first_fit',
    name: 'First Fit (Malloc Reuse)',
    category: 'technique',
    stack: [],
    format: [],
    heap: ['heap-based'],
    sandbox: [],
    description: 'Foundational heap behavior: malloc returns the most recently freed chunk of matching size (LIFO). Understanding this is essential for UAF, double-free, and tcache poisoning attacks.',
    prerequisites: ['Ability to allocate and free chunks of same size', 'Observation of malloc reuse behavior'],
    constraints: ['Purely educational — no direct exploit', 'LIFO only for fastbins and tcache'],
    blueprint: 'first_fit() {\n  a = malloc(0x60);\n  free(a);\n  c = malloc(0x60);  // c == a\n  // type confusion: c overwrites stale a\n}',
    children: [],
  },

  poison_null_byte: {
    id: 'poison_null_byte',
    name: 'Poison Null Byte',
    category: 'technique',
    stack: [],
    format: [],
    heap: ['heap-based'],
    sandbox: [],
    description: 'Off-by-one null byte overflow that clears PREV_IN_USE and forges prev_size, causing backward coalescing and overlapping chunks.',
    prerequisites: ['Off-by-one null byte vulnerability', 'Chunk layout control', 'Understanding of PREV_IN_USE and coalescing'],
    constraints: ['Glibc 2.29+ adds harder checks', 'Single null byte only'],
    blueprint: 'poison_null() {\n  overflow_null_into_next();\n  clear_prev_in_use();\n  forge_prev_size();\n  free(next);  // backward coalesce to fake chunk\n}',
    children: [],
  },

  house_of_husk: {
    id: 'house_of_husk',
    name: 'House of Husk',
    category: 'technique',
    stack: [],
    format: [],
    heap: ['heap-based'],
    sandbox: [],
    description: 'Corrupts __printf_function_table to redirect execution through crafted printf format specifier dispatch.',
    prerequisites: ['Libc leak', 'Heap overflow/UAF to write to libc tables', 'Binary uses printf with format specifiers'],
    constraints: ['Requires libc leak', 'Glibc 2.23-2.31', 'Affected by safe-linking in 2.32+'],
    blueprint: 'husk() {\n  leak_libc();\n  corrupt_printf_function_table();\n  set_arginfo_to_one_gadget();\n  printf("%X");  // triggers one_gadget\n}',
    children: [],
  },

  house_of_corrosion: {
    id: 'house_of_corrosion',
    name: 'House of Corrosion',
    category: 'technique',
    stack: [],
    format: [],
    heap: ['heap-based'],
    sandbox: [],
    description: 'Shrinks top chunk via overflow, then allocates to reach __free_hook or other global variables for arbitrary write.',
    prerequisites: ['Heap overflow reaching top chunk', 'Distance calculation to target', 'Glibc < 2.32 for __free_hook'],
    constraints: ['Must know approximate heap-to-target distance', 'Top chunk must be accessible via overflow'],
    blueprint: 'corrosion() {\n  top_chunk->size = 1;\n  malloc(distance_to_free_hook);\n  hook_chunk = malloc(0x10);\n  *hook_chunk = one_gadget;\n  free("/bin/sh");\n}',
    children: [],
  },

  house_of_cat: {
    id: 'house_of_cat',
    name: 'House of Cat',
    category: 'technique',
    stack: [],
    format: [],
    heap: ['heap-based'],
    sandbox: [],
    description: 'Modern FSOP technique for glibc 2.35+: corrupts _IO_wide_data vtable to bypass vtable verification and redirect execution through _IO_wfile_overflow.',
    prerequisites: ['Libc leak', 'Controlled write to _IO_FILE._wide_data', 'Exit or IO flush trigger'],
    constraints: ['Requires libc leak', 'Must stay within _IO_wfile_jumps range', 'Complex fake struct setup'],
    blueprint: 'cat() {\n  corrupt_wide_data_ptr();\n  set_wide_vtable_to_wfile_jumps();\n  set_flags_for_wide_path();\n  exit(0);  // triggers _IO_wfile_overflow → one_gadget\n}',
    children: [],
  },

  house_of_banana: {
    id: 'house_of_banana',
    name: 'House of Banana',
    category: 'technique',
    stack: [],
    format: [],
    heap: ['heap-based'],
    sandbox: [],
    description: '_IO_wstr_overflow chain, variant FSOP more modern than Apple/Cat for glibc 2.35+',
    prerequisites: ['Libc leak', 'Controlled write to _IO_FILE._wide_data', 'Trigger via exit()'],
    constraints: ['Requires libc leak', 'Must understand _IO_wstr_jumps path'],
    blueprint: 'banana() {\n  corrupt_wide_data_ptr();\n  set_wstr_vtable_to_wstr_jumps();\n  exit(0);\n}',
    children: [],
  },

  house_of_emma: {
    id: 'house_of_emma',
    name: 'House of Emma',
    category: 'technique',
    stack: [],
    format: [],
    heap: ['heap-based'],
    sandbox: [],
    description: '_IO_cookie_jumps + TTY vtable hijack for cookie-based IO dispatch',
    prerequisites: ['Libc leak', 'Controlled write to _IO_FILE._cookie and _vtable'],
    constraints: ['Requires libc leak', 'Cookie-based IO required'],
    blueprint: 'emma() {\n  set_cookie_ptr(controlled);\n  set_vtable_to_cookie_jumps();\n  trigger_cookie_io();\n}',
    children: [],
  },

  house_of_blaze: {
    id: 'house_of_blaze',
    name: 'House of Blaze',
    category: 'technique',
    stack: [],
    format: [],
    heap: ['heap-based'],
    sandbox: [],
    description: '_IO_wfile_underflow + large bin corruption combo for wide-char FSOP chain',
    prerequisites: ['Libc leak', 'Large bin attack capability', 'Controlled write to _IO_FILE'],
    constraints: ['Requires large bin attack', 'Complex multi-stage setup'],
    blueprint: 'blaze() {\n  large_bin_attack_write();\n  forge_fake_file_with_wide_chain();\n  exit(0);\n}',
    children: [],
  },

  house_of_fun: {
    id: 'house_of_fun',
    name: 'House of Fun',
    category: 'technique',
    stack: [],
    format: [],
    heap: ['heap-based'],
    sandbox: [],
    description: 'Tcache stashing unlink variant with different trigger path from classic calloc stashing',
    prerequisites: ['Glibc 2.26-2.31', 'Tcache + smallbin setup', 'calloc or specific malloc trigger'],
    constraints: ['Glibc version specific', 'Requires specific malloc/calloc trigger'],
    blueprint: 'fun() {\n  set_up_tcache_stashing();\n  corrupt_smallbin_bk();\n  trigger_malloc_not_calloc();\n}',
    children: [],
  },

  house_of_error: {
    id: 'house_of_error',
    name: 'House of Error',
    category: 'technique',
    stack: [],
    format: [],
    heap: ['heap-based'],
    sandbox: [],
    description: 'Arbitrary address free via tcache key manipulation and metadata corruption',
    prerequisites: ['Write primitive to tcache_perthread_struct', 'Glibc 2.26-2.31'],
    constraints: ['Tcache key era', 'Requires precise metadata manipulation'],
    blueprint: 'error() {\n  corrupt_tcache_entries();\n  set_target_count();\n  free(target_addr);\n}',
    children: [],
  },

  house_of_blind: {
    id: 'house_of_blind',
    name: 'House of Blind',
    category: 'technique',
    stack: [],
    format: [],
    heap: ['heap-based'],
    sandbox: [],
    description: 'Blind __free_hook replacement without libc leak (modern glibc 2.34+)',
    prerequisites: ['No libc leak', 'Glibc 2.34+ (hooks removed)', 'Alternative hook target'],
    constraints: ['No leak available', 'Modern glibc only'],
    blueprint: 'blind() {\n  partial_overwrite_alternative_hook();\n  place_gadget_on_heap();\n  trigger_free();\n}',
    children: [],
  },

  house_of_crane: {
    id: 'house_of_crane',
    name: 'House of Crane',
    category: 'technique',
    stack: [],
    format: [],
    heap: ['heap-based'],
    sandbox: [],
    description: 'Non-adjacent malloc consolidation trick via prev_size manipulation',
    prerequisites: ['Overflow to corrupt prev_size', 'malloc_consolidate trigger'],
    constraints: ['Requires prev_size corruption', 'Non-adjacent consolidation understanding'],
    blueprint: 'crane() {\n  corrupt_prev_size();\n  trigger_consolidate();\n  get_overlapping_chunks();\n}',
    children: [],
  },

  house_of_atum: {
    id: 'house_of_atum',
    name: 'House of Atum',
    category: 'technique',
    stack: [],
    format: [],
    heap: ['heap-based'],
    sandbox: [],
    description: 'Fastbin reverse + tcache stashing combo, two-stage exploit chain',
    prerequisites: ['Fastbin attack capability', 'Glibc 2.26-2.31', 'Two-stage setup'],
    constraints: ['Glibc version specific', 'Complex two-stage'],
    blueprint: 'atum() {\n  stage1_fastbin_reverse();\n  write_for_stage2_setup();\n  trigger_tcache_stashing();\n}',
    children: [],
  },

  house_of_kiwi: {
    id: 'house_of_kiwi',
    name: 'House of Kiwi',
    category: 'technique',
    stack: [],
    format: [],
    heap: ['heap-based'],
    sandbox: [],
    description: 'Small bin corruption + tcache, similar to House of Fun but different trigger path',
    prerequisites: ['Smallbin-sized overflow', 'Glibc 2.26-2.31', 'Tcache manipulation'],
    constraints: ['Glibc version specific', 'Different from House of Fun trigger'],
    blueprint: 'kiwi() {\n  corrupt_smallbin_bk();\n  manipulate_tcache_entries();\n  trigger_malloc();\n}',
    children: [],
  },

  house_of_card: {
    id: 'house_of_card',
    name: 'House of Card',
    category: 'technique',
    stack: [],
    format: [],
    heap: ['heap-based'],
    sandbox: [],
    description: 'Double free disguised via tcache key bypass, enables double-free exploitation',
    prerequisites: ['Write to tcache chunk key field', 'Glibc 2.26-2.31'],
    constraints: ['Tcache key era', 'Key field write required'],
    blueprint: 'card() {\n  free_chunk();\n  overwrite_key_field();\n  free_again_bypassed();\n}',
    children: [],
  },

  // FSOP BRANCH
  fsop_exploit: {
    id: 'fsop_exploit',
    name: 'File Stream Exploitation (FSOP)',
    category: 'recon',
    stack: [],
    format: [],
    heap: ['heap-based'], // often combined with heap
    sandbox: [],
    description: 'File Stream Oriented Programming - corrupts _IO_FILE structures (like stdin, stdout, stderr) to hijack control flow',
    prerequisites: ['Arbitrary write or heap overflow on FILE structs'],
    constraints: ['Glibc version specific vtable mitigations'],
    blueprint: 'fsop() {\n  corrupt_FILE_vtable();\n  trigger_IO_flush();\n}',
    children: ['house_of_apple', 'house_of_orange'],
  },

  house_of_apple: {
    id: 'house_of_apple',
    name: 'House of Apple (1 & 2)',
    category: 'technique',
    stack: [],
    format: [],
    heap: ['heap-based'],
    sandbox: [],
    description: 'Exploits modern glibc by hijacking _IO_FILE chains via _IO_wstr_jumps or _IO_wfile_jumps to achieve RCE',
    prerequisites: ['Glibc 2.34+ (post-hook removal)', 'Large arbitrary write'],
    constraints: ['Complex fake struct setup required'],
    blueprint: 'apple() {\n  forge_wide_data();\n  set_vtable_to_wstr_jumps();\n}',
    children: [],
  },

  house_of_orange: {
    id: 'house_of_orange',
    name: 'House of Orange',
    category: 'technique',
    stack: [],
    format: [],
    heap: ['heap-based'],
    sandbox: [],
    description: 'Corrupts top chunk size to trigger sysmalloc, yielding an unsorted bin chunk, then uses FSOP to get RCE during abort()',
    prerequisites: ['No free() call available', 'Glibc < 2.26'],
    constraints: ['Relies on abort() triggering _IO_flush_all_lockp'],
    blueprint: 'orange() {\n  corrupt_top_chunk();\n  trigger_sysmalloc();\n  fsop_via_unsorted_bin();\n}',
    children: [],
  },

  // SANDBOX ESCAPE BRANCH
  sandbox_escape: {
    id: 'sandbox_escape',
    name: 'Sandbox Escape',
    category: 'recon',
    stack: [],
    format: [],
    heap: [],
    sandbox: ['sandbox-escape'],
    description: 'Breaks out of restricted execution environments (browsers, containers)',
    prerequisites: ['Sandbox architecture knowledge', 'IPC vulnerabilities'],
    constraints: ['Mitigation bypass required', 'Privilege escalation needed'],
    blueprint: 'sandbox_escape() {\n  const vuln = find_ipc_vulnerability();\n  escalate_privileges();\n  break_out_of_sandbox();\n}',
    children: ['privilege_escalation', 'ipc_exploit', 'dirty_cow', 'modprobe_path', 'ebpf_exploit'],
  },

  privilege_escalation: {
    id: 'privilege_escalation',
    name: 'Privilege Escalation',
    category: 'technique',
    stack: [],
    format: [],
    heap: [],
    sandbox: ['sandbox-escape'],
    description: 'Exploits a kernel bug (UAF, heap overflow, race, logic error) to elevate from unprivileged user to root. Common primitives: overwriting cred struct (uid=0), modifying modprobe_path, or ROP chaining to commit_creds(prepare_kernel_cred(0)).',
    prerequisites: ['Kernel vulnerability (CVE)', 'Local or remote execution on target', 'Knowledge of target kernel version and protections'],
    constraints: ['SMEP (blocks ret2usr)', 'SMAP (blocks user memory access from kernel)', 'KASLR (randomizes kernel base)', 'KPTI (isolates user/kernel page tables)'],
    blueprint: `kernel_priv_esc() {
  // Option A: Overwrite cred struct
  task_struct = find_task_struct();
  task_struct.cred.uid = 0;  // become root
  
  // Option B: modprobe_path overwrite
  // Write "/tmp/x" to kernel's modprobe_path
  // Trigger unknown-binary exec → /tmp/x runs as root
  
  // Option C: Kernel ROP
  // commit_creds(prepare_kernel_cred(0)) → root shell
}`,
    children: ['kernel_rce', 'capability_abuse', 'ret2usr'],
  },

  ipc_exploit: {
    id: 'ipc_exploit',
    name: 'IPC Vulnerability',
    category: 'technique',
    stack: [],
    format: [],
    heap: [],
    sandbox: ['sandbox-escape'],
    description: 'Exploits inter-process communication to send malicious messages',
    prerequisites: ['IPC interface accessible', 'Message validation weak'],
    constraints: ['Broker implementation details', 'Message format specific'],
    blueprint: 'exploit_ipc() {\n  const channel = create_ipc_channel();\n  const payload = craft_malicious_message();\n  send_to_broker(channel, payload);\n}',
    children: ['mojo_exploit'],
  },

  kernel_rce: {
    id: 'kernel_rce',
    name: 'Kernel RCE',
    category: 'leaf',
    stack: [],
    format: [],
    heap: [],
    sandbox: ['sandbox-escape'],
    description: 'Achieves arbitrary code execution in kernel space (ring 0). Most commonly via kernel ROP chain → commit_creds(prepare_kernel_cred(0)) to become root, or by hijacking kernel function pointers.',
    prerequisites: ['Kernel arbitrary execution primitive', 'KASLR bypass', 'SMEP bypass (via ROP or CR4 flip)'],
    constraints: ['SMEP prevents ret2usr', 'SMAP blocks user memory access from kernel', 'KPTI complicates return to user space'],
    blueprint: `kernel_rce_exploit() {
  // 1. Leak kernel base (KASLR bypass)
  kernel_base = leak_via_proc_kallsyms_or_heap_leak();
  
  // 2. Build kernel ROP chain
  // pop rdi; ret → 0 (arg to prepare_kernel_cred)
  // → prepare_kernel_cred
  // → pop rdi; ret → return_value
  // → commit_creds
  // → iretq or swapgs_restore to return to user space
  
  // 3. Trigger the vulnerability to execute the ROP chain
  trigger_kernel_bug(rop_chain);
  
  // 4. Back in user space: execve("/bin/sh") → root shell
}`,
    children: ['msg_msg_corruption', 'userfaultfd_exploit'],
  },

  msg_msg_corruption: {
    id: 'msg_msg_corruption',
    name: 'msg_msg Struct Corruption',
    category: 'leaf',
    stack: [],
    format: [],
    heap: [],
    sandbox: ['sandbox-escape'],
    description: 'Corrupting the m_ts (size) or m_list pointers in the kernel msg_msg structure to achieve arbitrary read/write in kernel heap (kmalloc).',
    prerequisites: ['Kernel heap out-of-bounds or UAF', 'CONFIG_SYSVIPC enabled'],
    constraints: ['Requires precise kernel heap shaping (SLUB allocator)'],
    blueprint: 'msg_msg_exploit() {\n  spray_msg_msg();\n  trigger_oob_write_corrupt_size();\n  read_msg_for_leak();\n}',
    children: [],
  },

  userfaultfd_exploit: {
    id: 'userfaultfd_exploit',
    name: 'userfaultfd Exploitation',
    category: 'leaf',
    stack: [],
    format: [],
    heap: [],
    sandbox: ['sandbox-escape'],
    description: 'Using userfaultfd to pause kernel execution during a copy_from_user call, widening race condition windows infinitely for TOCTOU attacks.',
    prerequisites: ['userfaultfd syscall allowed', 'Race condition vulnerability'],
    constraints: ['Blocked in newer kernels for unprivileged users (unprivileged_userfaultfd=0)'],
    blueprint: 'uffd() {\n  setup_uffd_page();\n  trigger_kernel_copy_from_user();\n  // execution pauses\n  swap_pointers_in_another_thread();\n  release_uffd();\n}',
    children: [],
  },

  ebpf_exploit: {
    id: 'ebpf_exploit',
    name: 'eBPF Verifier Bypass',
    category: 'technique',
    stack: [],
    format: [],
    heap: [],
    sandbox: ['sandbox-escape'],
    description: 'Tricks the kernel eBPF verifier\'s static analysis into loading a BPF program that accesses memory beyond verifier-approved bounds. The BPF can then read/write arbitrary kernel memory, enabling privilege escalation.',
    prerequisites: ['CAP_BPF or CAP_SYS_ADMIN (or unprivileged_bpf_disabled=0)', 'Vulnerable kernel with verifier bug (CVE)', 'Knowledge of eBPF instruction set and verifier architecture'],
    constraints: ['Extremely complex: requires deep kernel internals knowledge', 'Each kernel version has different verifier bugs', 'Often requires BPF JIT enabled'],
    blueprint: `ebpf_verifier_bypass() {
  // Craft BPF bytecode that tricks the verifier:
  // 1. Make verifier think register is bounded [0, N]
  // 2. At runtime, register holds >> N → OOB access
  // 3. Use OOB map access to leak kernel pointers (KASLR bypass)
  // 4. Use BPF helper (bpf_map_update_elem) to write to kernel mem
  // 5. Overwrite modprobe_path → root shell
}`,
    children: ['kernel_rce'],
  },

  capability_abuse: {
    id: 'capability_abuse',
    name: 'Capability Abuse',
    category: 'leaf',
    stack: [],
    format: [],
    heap: [],
    sandbox: ['sandbox-escape'],
    description: 'Misuses Linux capabilities for privilege escalation',
    prerequisites: ['CAP_SYS_ADMIN available', 'Capability misconfiguration'],
    constraints: ['Container/namespace setup'],
    blueprint: 'abuse_capability() {\n  const cap = get_available_capability();\n  use_for_privilege_escalation();\n  spawn_unrestricted_shell();\n}',
    children: [],
  },

  mojo_exploit: {
    id: 'mojo_exploit',
    name: 'Mojo/IPC RCE',
    category: 'leaf',
    stack: [],
    format: [],
    heap: [],
    sandbox: ['sandbox-escape'],
    description: 'Exploits Mojo IPC framework in browser/container environments',
    prerequisites: ['Mojo interface defined', 'Type confusion possible'],
    constraints: ['Mojo version specific', 'Serialization details'],
    blueprint: 'exploit_mojo() {\n  const binding = create_mojo_binding();\n  const rce = build_type_confusion();\n  send_exploit_message(rce);\n}',
    children: [],
  },

  dirty_cow: {
    id: 'dirty_cow',
    name: 'Dirty COW (CVE-2016-5195)',
    category: 'technique',
    stack: [],
    format: [],
    heap: [],
    sandbox: ['sandbox-escape'],
    description: 'Exploits a race condition in Linux memory management (Copy-On-Write) to write to read-only files (like /etc/passwd or SUID binaries)',
    prerequisites: ['Kernel < 4.8.3', 'Local access'],
    constraints: ['Can cause system instability'],
    blueprint: 'dirty_cow() {\n  mmap_read_only_file();\n  thread1_madvise_dontneed();\n  thread2_write_proc_self_mem();\n}',
    children: [],
  },

  modprobe_path: {
    id: 'modprobe_path',
    name: 'modprobe_path Overwrite',
    category: 'leaf',
    stack: [],
    format: [],
    heap: [],
    sandbox: ['sandbox-escape'],
    description: 'Kernel exploit technique that overwrites core_pattern or modprobe_path to execute an arbitrary script as root',
    prerequisites: ['Arbitrary write in kernel space'],
    constraints: ['Requires KASLR bypass to find modprobe_path'],
    blueprint: 'modprobe() {\n  write_kernel_addr(modprobe_path, "/tmp/x");\n  trigger_unknown_executable();\n}',
    children: [],
  },

  ret2usr: {
    id: 'ret2usr',
    name: 'ret2usr',
    category: 'leaf',
    stack: [],
    format: [],
    heap: [],
    sandbox: ['sandbox-escape'],
    description: 'Kernel exploitation technique that redirects kernel execution to a user-space function to escalate privileges',
    prerequisites: ['Kernel arbitrary execution', 'SMEP disabled'],
    constraints: ['Blocked by SMEP (Supervisor Mode Execution Protection)'],
    blueprint: 'ret2usr() {\n  hijack_kernel_ptr(user_space_payload);\n  // user_space_payload: commit_creds(prepare_kernel_cred(0))\n}',
    children: [],
  },

  // INTEGER EXPLOITS BRANCH
  integer_exploits: {
    id: 'integer_exploits',
    name: 'Integer Vulnerabilities',
    category: 'root',
    stack: [],
    format: [],
    heap: [],
    sandbox: [],
    description: 'Exploits arithmetic bugs: overflow (wrap past max), underflow (wrap below zero), sign extension (negative narrow → huge wide), and signed/unsigned mismatches. Often the root cause that enables buffer overflows.',
    prerequisites: [],
    constraints: [],
    blueprint: `INTEGER VULN ANALYSIS
====================
1. Check types: signed int vs unsigned size_t vs char
2. Find arithmetic before malloc/read/memcpy: size_calc = user_input + constant
3. Edge cases: user_input = 0xFFFFFFFF → size_calc wraps to constant-1
4. Underflow: size = 0; if (size - 1 > MAX) → 0-1 = 0xFFFFFFFF > MAX
5. Sign extension: char(-1) → sign-extended to int → 0xFFFFFFFF
6. Test: send 0, -1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF`,
    children: ['integer_overflow', 'integer_underflow', 'sign_extension', 'off_by_one'],
  },

  integer_overflow: {
    id: 'integer_overflow',
    name: 'Integer Overflow',
    category: 'recon',
    stack: ['stack-based'],
    format: [],
    heap: ['heap-based'],
    sandbox: [],
    description: 'An arithmetic result exceeds the maximum value of its storage type (e.g., 0xFFFFFFFF + 1 = 0x00000000 for 32-bit unsigned). Used to make malloc(0) while copying gigabytes, or to bypass size checks.',
    prerequisites: ['Unchecked arithmetic on allocation sizes or array indexes', 'User-controlled size input'],
    constraints: ['Need to find a code path where the overflowed value is used as size/count'],
    blueprint: `int_overflow_exploit() {
  // Example: size = get_input(); buf = malloc(size + 0x10);
  // User sends 0xFFFFFFF0 → size+0x10 wraps to 0 (tiny alloc)
  // Program then does: read(0, buf, size) → copies 4GB into 0-byte buffer!
  
  send_size(0xFFFFFFF0);
  // Or: user_count * sizeof(element) can overflow
  // e.g., count = 0x40000001, sizeof = 4 → product = 4 (wraps!)
}`,
    children: ['buffer_overflow', 'heap_exploit'],
  },

  integer_underflow: {
    id: 'integer_underflow',
    name: 'Integer Underflow',
    category: 'recon',
    stack: ['stack-based'],
    format: [],
    heap: ['heap-based'],
    sandbox: [],
    description: 'Subtracting on an unsigned integer wraps it to near-maximum (e.g., 0 - 1 = 0xFFFFFFFF). Used to bypass "if (size-1 > MAX) fail" — since 0-1 is huge, the check passes and a giant value is used.',
    prerequisites: ['Unchecked subtraction on unsigned types'],
    constraints: ['The underflowed value must be used as size/count after the wrap'],
    blueprint: `int_underflow_exploit() {
  // size = 0;  (controlled by attacker)
  // if (size - 1 <= MAX) {  // 0-1 = 0xFFFFFFFF → check FAILS!
  //   memcpy(dst, src, size - 1); // copies 4GB to small buffer
  // }
  send_size(0);
  // Or: idx = user_input - 1; arr[idx] 
  // User sends idx=0 → arr[0xFFFFFFFF] = OOB write
}`,
    children: ['buffer_overflow'],
  },

  sign_extension: {
    id: 'sign_extension',
    name: 'Sign Extension Bug',
    category: 'technique',
    stack: ['stack-based'],
    format: [],
    heap: [],
    sandbox: [],
    description: 'A narrow signed type (e.g., int8_t = -1 = 0xFF) is implicitly or explicitly cast to a wider unsigned type (e.g., size_t), sign-extending the negative value to all 1s (0xFFFFFFFF). Results in huge unsigned values from small negative inputs.',
    prerequisites: ['Implicit or explicit cast from signed narrow type (char, int8_t, int16_t) to wider unsigned (size_t, uint32_t, uint64_t)'],
    constraints: ['Must find the specific cast site in disassembly/decompilation'],
    blueprint: `sign_extend_exploit() {
  // char len = get_user_byte();  // user sends \\xFF (-128)
  // int bufsize = len + 16;      // sign-extended: 0xFFFFFF00 + 16
  // char *buf = malloc(bufsize); // undersized allocation
  // memcpy(buf, src, bufsize);   // copies 4GB!
  
  // In C: int8_t → int32_t → size_t chain causes this
  // Spot in Ghidra: CAST instructions followed by zero-extend
  // (actually sign-extend via MOVSX/MOVSXD) before malloc/read
}`,
    children: ['buffer_overflow'],
  },

  off_by_one: {
    id: 'off_by_one',
    name: 'Off-by-One Error',
    category: 'technique',
    stack: ['stack-based'],
    format: [],
    heap: ['heap-based'],
    sandbox: [],
    description: 'A boundary check is off by exactly one (e.g., i <= length instead of i < length), allowing exactly 1 byte of attacker-controlled overflow. Powerful for corrupting saved RBP LSB (stack pivot) or chunk size PREV_INUSE bit (heap consolidation).',
    prerequisites: ['Loop with <= instead of <, or strncpy with wrong size, or NULL terminator past buffer'],
    constraints: ['Only 1 byte (maximum 255 values) of overflow — need precise targeting'],
    blueprint: `off_by_one_exploit() {
  // Stack: overwrite saved RBP LSB → redirect caller's frame
  payload = b'A' * buffer_size + b'\\\\x00'  // null byte overflow
  // → RBP LSB = 0 → frame shifts to lower stack address
  // → callers "leave" picks up fake frame + attacker's RIP
  
  // Heap: overflow into next chunk's size PREV_INUSE bit (bit 0)
  // + set prev_size to distance to fake chunk
  // → free(next) consolidates backward → overlapping chunks
  *(uint8_t*)(chunk_a + chunk_a_size) = 0x00; // clear PREV_INUSE
  *(chunk_a + chunk_a_size + 1) = fake_prev_size;
}`,
    children: ['stack_pivot', 'house_of_einherjar'],
  },

  // PREREQUISITES BRANCH
  prerequisites_root: {
    id: 'prerequisites_root',
    name: 'Prerequisites & Concepts',
    category: 'root',
    stack: [],
    format: [],
    heap: [],
    sandbox: [],
    description: 'Fundamental concepts and knowledge required before exploitation',
    prerequisites: [],
    constraints: [],
    blueprint: 'understand_fundamentals();',
    children: ['memory_layout', 'calling_conventions', 'elf_format', 'plt_got', 'glibc_malloc'],
  },

  memory_layout: {
    id: 'memory_layout',
    name: 'Memory Layout',
    category: 'leaf',
    stack: [],
    format: [],
    heap: [],
    sandbox: [],
    description: 'Understanding of Process Memory Map: Text, Data, BSS, Heap, and Stack segments.',
    prerequisites: [],
    constraints: [],
    blueprint: 'cat /proc/$PID/maps',
    children: [],
  },

  calling_conventions: {
    id: 'calling_conventions',
    name: 'Calling Conventions',
    category: 'leaf',
    stack: [],
    format: [],
    heap: [],
    sandbox: [],
    description: 'How arguments are passed to functions (e.g., x64 Linux: rdi, rsi, rdx, rcx, r8, r9).',
    prerequisites: [],
    constraints: [],
    blueprint: 'mov rdi, arg1\nmov rsi, arg2\ncall func',
    children: [],
  },
  
  elf_format: {
    id: 'elf_format',
    name: 'ELF File Format',
    category: 'leaf',
    stack: [],
    format: [],
    heap: [],
    sandbox: [],
    description: 'Executable and Linkable Format: Sections, Segments, Program Headers.',
    prerequisites: [],
    constraints: [],
    blueprint: 'readelf -a binary',
    children: [],
  },

  plt_got: {
    id: 'plt_got',
    name: 'PLT / GOT',
    category: 'leaf',
    stack: [],
    format: [],
    heap: [],
    sandbox: [],
    description: 'Procedure Linkage Table and Global Offset Table mechanisms for dynamic linking.',
    prerequisites: [],
    constraints: [],
    blueprint: 'objdump -R binary | grep GOT',
    children: [],
  },

  glibc_malloc: {
    id: 'glibc_malloc',
    name: 'Glibc Malloc Internals',
    category: 'leaf',
    stack: [],
    format: [],
    heap: [],
    sandbox: [],
    description: 'Understanding chunks, arenas, bins (fast, unsorted, small, large), and tcache.',
    prerequisites: [],
    constraints: [],
    blueprint: 'ptype struct malloc_chunk',
    children: [],
  },

  // TOOLS BRANCH
  tools_root: {
    id: 'tools_root',
    name: 'Exploitation Tools',
    category: 'root',
    stack: [],
    format: [],
    heap: [],
    sandbox: [],
    description: 'Tools used during the exploit development process',
    prerequisites: [],
    constraints: [],
    blueprint: 'use_tools();',
    children: ['pwndbg', 'gef', 'pwntools', 'ropper', 'one_gadget'],
  },

  pwndbg: {
    id: 'pwndbg',
    name: 'pwndbg',
    category: 'leaf',
    stack: [],
    format: [],
    heap: [],
    sandbox: [],
    description: 'GDB plug-in that makes debugging with GDB suck less, with a focus on features needed by low-level software developers, hardware hackers, reverse-engineers and exploit developers.',
    prerequisites: [],
    constraints: [],
    blueprint: 'gdb ./binary\npwndbg> start',
    children: [],
  },
  
  gef: {
    id: 'gef',
    name: 'GEF',
    category: 'leaf',
    stack: [],
    format: [],
    heap: [],
    sandbox: [],
    description: 'GDB Enhanced Features for exploit devs & reversers.',
    prerequisites: [],
    constraints: [],
    blueprint: 'gdb ./binary\ngef> checksec',
    children: [],
  },

  pwntools: {
    id: 'pwntools',
    name: 'pwntools',
    category: 'leaf',
    stack: [],
    format: [],
    heap: [],
    sandbox: [],
    description: 'CTF framework and exploit development library for Python.',
    prerequisites: [],
    constraints: [],
    blueprint: 'from pwn import *\np = process("./binary")',
    children: [],
  },

  ropper: {
    id: 'ropper',
    name: 'Ropper',
    category: 'leaf',
    stack: [],
    format: [],
    heap: [],
    sandbox: [],
    description: 'You can use ropper to look at information about files in different file formats and you can search for gadgets to build rop chains for different architectures.',
    prerequisites: [],
    constraints: [],
    blueprint: 'ropper --file ./binary --search "pop rdi"',
    children: [],
  },

  one_gadget: {
    id: 'one_gadget',
    name: 'one_gadget',
    category: 'leaf',
    stack: [],
    format: [],
    heap: [],
    sandbox: [],
    description: 'Tool to find the one gadget execve("/bin/sh", NULL, NULL) call in libc.',
    prerequisites: [],
    constraints: [],
    blueprint: 'one_gadget /lib/x86_64-linux-gnu/libc.so.6',
    children: [],
  },

  // SETUP TOOLS BRANCH
  setup_tools_root: {
    id: 'setup_tools_root',
    name: 'Environment Setup',
    category: 'recon',
    stack: [],
    format: [],
    heap: [],
    sandbox: [],
    description: 'Essential tools and environment setup for binary exploitation. Install these before starting any pwn challenge.',
    prerequisites: ['Linux system (Ubuntu 20.04/22.04 recommended or WSL2)', 'Python 3.8+', 'Basic terminal proficiency'],
    constraints: ['Some tools require specific OS/architecture', 'IDA requires license for full features'],
    blueprint: 'setup_environment() {\n  install_gdb_pwndbg();\n  install_pwntools();\n  install_ghidra();\n  install_checksec();\n  configure_libc_databases();\n}',
    children: ['setup_gdb', 'setup_pwntools', 'setup_ghidra', 'setup_ida', 'setup_checksec', 'setup_ropper', 'setup_libc_db', 'setup_seccomp_tools', 'setup_patchelf', 'setup_qemu'],
  },

  setup_gdb: {
    id: 'setup_gdb',
    name: 'GDB + pwndbg',
    category: 'leaf',
    stack: [],
    format: [],
    heap: [],
    sandbox: [],
    description: 'GDB enhanced with pwndbg — the most important debugging tool for pwn. Provides heap visualization, context display, and exploit development helpers.',
    prerequisites: ['GDB installed (apt install gdb)', 'Git for cloning pwndbg', 'Python3 dev headers'],
    constraints: ['pwndbg requires Python 3.8+', 'Some features need gdb-multiarch for ARM/MIPS targets'],
    blueprint: `# Install GDB + pwndbg
sudo apt install gdb gdb-multiarch
cd ~
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh

# Verify
gdb ./binary
# pwndbg> checksec
# pwndbg> vmmap
# pwndbg> heap chunks
# pwndbg> telescope $rsp 20`,
    children: [],
  },

  setup_pwntools: {
    id: 'setup_pwntools',
    name: 'pwntools',
    category: 'leaf',
    stack: [],
    format: [],
    heap: [],
    sandbox: [],
    description: 'Python exploit development library — cyclic pattern generation, ROP chain building, tube abstraction for local/remote connections, and ELF parsing.',
    prerequisites: ['Python 3.8+ with pip', 'Linux system (WSL2 on Windows)'],
    constraints: ['Some features (ASM, shellcraft) require binutils for target architecture'],
    blueprint: `# Install pwntools
pip3 install pwntools

# Optional: install additional dependencies
sudo apt install binutils-arm-linux-gnueabihf  # ARM support
sudo apt install binutils-mips-linux-gnu        # MIPS support

# Verify
python3 -c "from pwn import *; print('pwntools OK')"

# Common pwntools patterns
from pwn import *
context.arch = 'amd64'
p = process('./binary')        # local
p = remote('host', 1337)       # remote
payload = cyclic(200)          # pattern
e = ELF('./binary')            # parse ELF`,
    children: [],
  },

  setup_ghidra: {
    id: 'setup_ghidra',
    name: 'Ghidra',
    category: 'leaf',
    stack: [],
    format: [],
    heap: [],
    sandbox: [],
    description: 'Free NSA reverse engineering suite — decompiler, disassembler, and scriptable analysis. Essential for understanding binary logic when source is unavailable.',
    prerequisites: ['Java JDK 17+', '4GB+ RAM for large binaries', 'Linux/macOS/Windows'],
    constraints: ['GUI required for full features', 'Headless mode available for scripting'],
    blueprint: `# Install Ghidra
sudo apt install default-jdk
cd ~
wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra11.2.1_build/ghidra_11.2.1_PUBLIC.zip
unzip ghidra_11.2.1_PUBLIC.zip
cd ghidra_11.2.1_PUBLIC
./ghidraRun

# Headless analysis (scriptable)
analyzeHeadless /tmp/project Binary \\
  -import ./binary -postScript MyScript.java

# Common workflow:
# 1. Import binary → Auto-Analyze
# 2. Search → Strings (find /bin/sh, flag paths)
# 3. Window → Functions (find vuln functions)
# 4. Decompile main(), handlers, read(), gets()`,
    children: [],
  },

  setup_ida: {
    id: 'setup_ida',
    name: 'IDA Pro',
    category: 'leaf',
    stack: [],
    format: [],
    heap: [],
    sandbox: [],
    description: 'Industry-standard disassembler and decompiler (Hex-Rays). Best-in-class decompilation, FLIRT signature matching, and plugin ecosystem. Free version available (IDA Free).',
    prerequisites: ['IDA Pro license (paid) or IDA Free (limited)', 'Windows/Linux/macOS', 'Python 3 for IDAPython scripting'],
    constraints: ['IDA Free does not include Hex-Rays decompiler', 'No ARM/MIPS in free version', 'Paid version needed for full feature set'],
    blueprint: `# IDA Pro setup
# 1. Download from https://hex-rays.com/ida-pro/
# 2. Install and activate license
# 3. Install Hex-Rays decompiler (amd64/arm')

# IDAPython scripting essentials
import idautils, idc, idaapi

# Find all calls to dangerous functions
for func_ea in idautils.Functions():
    name = idc.get_func_name(func_ea)
    if name in ['gets', 'strcpy', 'sprintf', 'read']:
        for xref in idautils.XrefsTo(func_ea):
            print(f"  {name} called at 0x{xref.frm:X}")

# Recommended plugins:
# - LazyIDA: copy-paste helpers
# - Keypatch: assemble/patch instructions
# - FindCrypt: identify crypto constants`,
    children: [],
  },

  setup_checksec: {
    id: 'setup_checksec',
    name: 'checksec',
    category: 'leaf',
    stack: [],
    format: [],
    heap: [],
    sandbox: [],
    description: 'Binary protection checker — reports NX, PIE, Canary, RELRO, ASLR status. Always run this first on any target binary.',
    prerequisites: ['None (standalone binary)', 'Python 3 for pwntools version'],
    constraints: ['checksec from checksec.sh is different from pwntools checksec'],
    blueprint: `# Install checksec
# Option 1: pwntools version (recommended)
pip3 install pwntools
# Then: pwn checksec ./binary

# Option 2: standalone script
sudo apt install checksec

# Usage
checksec --file=./binary
# Output: NX, PIE, Canary, RELRO status

# pwntools version (more detailed)
pwn checksec ./binary

# In Python:
from pwn import *
e = ELF('./binary')
print(f"NX: {e.execstack}")        # No-Execute
print(f"PIE: {e.pie}")             # Position Independent
print(f"Canary: {e.canary}")       # Stack canary
print(f"RELRO: {e.relro}")         # RELRO level`,
    children: [],
  },

  setup_ropper: {
    id: 'setup_ropper',
    name: 'ROPgadget + ropper',
    category: 'leaf',
    stack: [],
    format: [],
    heap: [],
    sandbox: [],
    description: 'ROP gadget search tools — find gadgets for building ROP chains. ROPgadget is the classic, ropper provides cleaner output and chain building.',
    prerequisites: ['capstone (pip install capstone) for ropper', 'Binary to search'],
    constraints: ['Gadget quality depends on binary size and compiler', 'Some gadgets may be unreachable'],
    blueprint: `# Install
pip3 install ropper
sudo apt install ruby && gem install one_gadget

# ROPgadget (comes with pwntools)
ROPgadget --binary ./binary --ropchain

# ropper
ropper --file ./binary --search "pop rdi; ret"
ropper --file ./binary --chain "execve"

# one_gadget (libc one-shot RCE)
one_gadget /lib/x86_64-linux-gnu/libc.so.6

# pwntools ROP
from pwn import *
rop = ROP(ELF('./binary'))
rop.call('system', ['/bin/sh'])
print(rop.dump())`,
    children: [],
  },

  setup_libc_db: {
    id: 'setup_libc_db',
    name: 'libc-database',
    category: 'leaf',
    stack: [],
    format: [],
    heap: [],
    sandbox: [],
    description: 'Offline libc fingerprint database — identify exact libc version from leaked function offsets. Critical for remote exploitation where the target libc differs from local.',
    prerequisites: ['Git', 'Disk space (~2GB for full database)', 'Internet for initial download'],
    constraints: ['Database must be updated periodically for new libc versions', 'Online alternative: libc.rip'],
    blueprint: `# Install libc-database
cd ~
git clone https://github.com/niklasb/libc-database
cd libc-database

# Download common libc versions (takes time)
./get ubuntu           # Ubuntu libc versions
./get debian           # Debian libc versions

# Identify libc from leaked offsets
./identify leaked_printf_offset
# Example: ./identify printf 0x7f1234567890

# Find symbols in identified libc
./dump libc_id system "/bin/sh"
# Output: system offset, /bin/sh offset, one_gadget offsets

# Online alternative: https://libc.rip
# Provide 2+ function offsets → exact libc match

# pwntools integration
from pwn import *
libc = ELF('./identified_libc.so')
system = libc.symbols['system']
binsh = next(libc.search(b'/bin/sh'))`,
    children: [],
  },

  setup_seccomp_tools: {
    id: 'setup_seccomp_tools',
    name: 'seccomp-tools',
    category: 'leaf',
    stack: [],
    format: [],
    heap: [],
    sandbox: [],
    description: 'Dump and analyze seccomp-BPF filter rules. Determine which syscalls are allowed/blocked before building exploit chains (open+read+write vs execve).',
    prerequisites: ['Ruby installed (apt install ruby)', 'Kernel with seccomp support'],
    constraints: ['Must run on target binary or same architecture', 'Some CTFs modify BPF rules at runtime'],
    blueprint: `# Install seccomp-tools
gem install seccomp-tools

# Dump seccomp rules of running binary
seccomp-tools dump ./binary
# Or with input:
echo "input" | seccomp-tools dump ./binary

# Common output interpretation:
# ALLOW: open, read, write, exit  → ORW chain possible
# ALLOW: openat, sendfile          → Alternative ORW
# KILL:  execve                    → MUST use ORW, no shell

# Build ORW chain if execve is blocked
from pwn import *
rop = ROP(elf)
rop.call('open', ['./flag', 0])
rop.call('read', [3, buf, 100])
rop.call('write', [1, buf, 100])`,
    children: [],
  },

  setup_patchelf: {
    id: 'setup_patchelf',
    name: 'patchelf + pwninit',
    category: 'leaf',
    stack: [],
    format: [],
    heap: [],
    sandbox: [],
    description: 'Patch ELF interpreter and RPATH to use the correct libc version locally. Essential for testing exploits with the same libc as the remote target.',
    prerequisites: ['patchelf binary (apt install patchelf)', 'Target libc.so and ld-linux.so from remote', 'pwninit (pip install pwninit)'],
    constraints: ['Must have matching libc.so and ld-linux for target architecture', 'Some glibc versions are incompatible'],
    blueprint: `# Install
sudo apt install patchelf
pip3 install pwninit

# Method 1: pwninit (automated, recommended)
# Place: binary, libc.so.6, ld-linux-x86-64.so.2 in same dir
pwninit
# Auto-creates: ./binary_patched with correct interpreter

# Method 2: Manual patchelf
patchelf --set-interpreter ./ld-linux-x86-64.so.2 ./binary
patchelf --set-rpath . ./binary

# Verify
ldd ./binary
# Should show ./libc.so.6 as libc

# Test locally
./binary_patched  # uses target libc
# Confirm with:
pwn checksec ./binary_patched`,
    children: [],
  },

  setup_qemu: {
    id: 'setup_qemu',
    name: 'QEMU + gdb-multiarch',
    category: 'leaf',
    stack: [],
    format: [],
    heap: [],
    sandbox: [],
    description: 'Emulate and debug ARM, MIPS, AArch64 binaries locally. Required for cross-architecture pwn challenges.',
    prerequisites: ['QEMU user-mode emulator', 'gdb-multiarch', 'Target architecture binutils (arm, mips, aarch64)'],
    constraints: ['QEMU user-mode only emulates user-space (no kernel exploits)', 'Some syscalls may differ from real hardware'],
    blueprint: `# Install
sudo apt install qemu-user qemu-user-static gdb-multiarch \\
  binutils-arm-linux-gnueabihf binutils-mips-linux-gnu \\
  binutils-aarch64-linux-gnu

# Run ARM binary
qemu-arm ./arm_binary
qemu-arm -L /usr/arm-linux-gnueabihf ./arm_binary  # with sysroot

# Debug with QEMU + GDB
qemu-arm -g 1234 ./arm_binary &
gdb-multiarch ./arm_binary
# (gdb) set architecture arm
# (gdb) target remote :1234

# pwntools integration
from pwn import *
context.arch = 'arm'
context.binary = ELF('./arm_binary')
p = process(['qemu-arm', '-g', '1234', './arm_binary'])
# Or:
p = gdb.debug('./arm_binary', arch='arm')`,
    children: [],
  },
};

export const getChildrenIds = (parentId: string): string[] => {
  return PWN_TECHNIQUES[parentId]?.children || [];
};

export const getTechniquesByCategory = (category: keyof typeof PWN_TECHNIQUES): Technique[] => {
  return Object.values(PWN_TECHNIQUES).filter((t) => t.category === category);
};
