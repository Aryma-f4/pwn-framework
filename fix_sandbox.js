const fs = require('fs');

let content = fs.readFileSync('lib/pwn-knowledge-base.ts', 'utf8');

const sandboxReplacement = `  sandbox_escape: {
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
        '1. Dump rules: \`seccomp-tools dump ./binary\`',
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
        codeSnippet: \`rop.call('open', [flag_str_addr, 0])
rop.call('read', [3, bss_buffer, 0x100])
rop.call('write', [1, bss_buffer, 0x100])\`
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
  },`;

const sandboxRegex = /  sandbox_escape: \{[\s\S]*?vulnerabilityTypes: \['sandbox'\],\n    \n    references: \[\n      \{ tool: 'seccomp-tools', description: 'Dump and analyze seccomp BPF filters', url: 'https:\/\/github\.com\/david942j\/seccomp-tools' \},\n      \{ description: 'Seccomp Exploitation Techniques', url: 'https:\/\/lkmidas\.github\.io\/posts\/20210105-seccomp\/' \},\n      \{ tool: 'pwntools', description: 'ROP gadget chaining for syscall automation' \}\n    \]\n  \},/g;

if(content.match(sandboxRegex)) {
  content = content.replace(sandboxRegex, sandboxReplacement);
  console.log("Replaced Sandbox Escape!");
} else {
  console.log("Sandbox regex did not match!");
}

fs.writeFileSync('lib/pwn-knowledge-base.ts', content);

