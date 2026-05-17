export interface Technique {
  id: string;
  name: string;
  category: 'recon' | 'mitigation' | 'technique' | 'leaf';
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
    name: 'PWN Exploitation Tree',
    category: 'root',
    stack: [],
    format: [],
    heap: [],
    sandbox: [],
    description: 'Interactive decision tree for exploitation techniques across different vulnerability types',
    prerequisites: [],
    constraints: [],
    blueprint: '',
    children: ['buffer_overflow', 'format_string', 'heap_exploit', 'sandbox_escape'],
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
    children: ['stack_pivot', 'rop_chain'],
  },

  stack_pivot: {
    id: 'stack_pivot',
    name: 'Stack Pivot',
    category: 'technique',
    stack: ['stack-based'],
    format: [],
    heap: [],
    sandbox: [],
    description: 'Manipulates ESP/RSP to control stack layout and gadget execution',
    prerequisites: ['ROP gadgets available', 'Writable memory regions'],
    constraints: ['Address layout predictability required'],
    blueprint: 'pivot_stack() {\n  const new_stack = find_writable_region();\n  set_rsp(new_stack);\n  execute_gadget_chain();\n}',
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
    children: ['format_leak', 'format_write'],
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
    children: ['use_after_free', 'double_free'],
  },

  use_after_free: {
    id: 'use_after_free',
    name: 'Use-After-Free',
    category: 'technique',
    stack: [],
    format: [],
    heap: ['heap-based'],
    sandbox: [],
    description: 'Accesses memory after it has been freed, enabling exploitation',
    prerequisites: ['Memory free call accessible', 'Dangling pointer usage'],
    constraints: ['Heap state predictability', 'Object reuse timing'],
    blueprint: 'uaf_exploit() {\n  const obj = allocate_object();\n  free(obj);\n  reallocate_controlled();\n  use_freed_pointer(obj);\n}',
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
    children: ['privilege_escalation', 'ipc_exploit'],
  },

  privilege_escalation: {
    id: 'privilege_escalation',
    name: 'Privilege Escalation',
    category: 'technique',
    stack: [],
    format: [],
    heap: [],
    sandbox: ['sandbox-escape'],
    description: 'Elevates permissions from restricted to unrestricted execution',
    prerequisites: ['Kernel vulnerability', 'SUID binary', 'Capability error'],
    constraints: ['Kernel version specific', 'Patch level dependent'],
    blueprint: 'escalate() {\n  const exploit = load_kernel_exploit();\n  exploit.execute();\n  verify_root_access();\n}',
    children: ['kernel_rce', 'capability_abuse'],
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
    description: 'Achieves remote code execution in kernel space',
    prerequisites: ['Kernel vulnerability', 'Working exploit PoC'],
    constraints: ['SMEP/SMAP evasion', 'KASLR bypass'],
    blueprint: 'kernel_rce() {\n  const rip = leak_kernel_addr();\n  const chain = build_kernel_rop(rip);\n  trigger_kernel_crash(chain);\n}',
    children: [],
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
};

export const getChildrenIds = (parentId: string): string[] => {
  return PWN_TECHNIQUES[parentId]?.children || [];
};

export const getTechniquesByCategory = (category: keyof typeof PWN_TECHNIQUES): Technique[] => {
  return Object.values(PWN_TECHNIQUES).filter((t) => t.category === category);
};
