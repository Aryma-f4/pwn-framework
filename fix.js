const fs = require('fs');

let content = fs.readFileSync('lib/pwn-knowledge-base.ts', 'utf8');

// The replacement payload
const formatReplacement = `  format_string_vulnerability: {
    id: 'format_string_vulnerability',
    name: 'Format String Vulnerability (FSB)',
    category: 'technique',
    class: 'Format String Exploitation',
    description: 'Exploit printf-family functions with user-controlled format strings for arbitrary read/write.',
    
    preconditions: {
      summary: 'User input used as format string argument without "%s".',
      required: [
        'Vulnerable func: printf(user_input)',
        'Controllable input string'
      ],
      detectionSteps: [
        '1. Fuzz: Send \`%p.%p.%p\`',
        '2. Verify: Output shows memory addresses',
        '3. Find Offset: Send \`AAAA.%p.%p...\` until \`0x41414141\` appears'
      ],
      offsetDiscovery: {
        'pwntools FmtStr': 'def exec_fmt(p): ...; fmt = FmtStr(exec_fmt)',
        'manual': 'Send "AAAA" + ".%p"*N until 0x41414141 appears'
      }
    },
    
    exploitationPaths: [
      {
        name: 'Arbitrary Read (Memory Leak)',
        description: 'Read stack contents or specific memory addresses.',
        steps: [
          '1. Find target address to leak (e.g., GOT entry for puts)',
          '2. Find the offset of your input on the stack',
          '3. Build payload: [Address] + %<offset>$s'
        ],
        tools: ['pwntools fmtstr'],
        codeSnippet: \`payload = p64(got_puts) + b'%7$s'
p.sendline(payload)\`
      },
      {
        name: 'Arbitrary Write (%n)',
        description: 'Write data to arbitrary memory addresses.',
        steps: [
          '1. Find target address to write (e.g., GOT entry for printf)',
          '2. Find the offset of your input on the stack',
          '3. Build payload: Write system() address to printf GOT'
        ],
        tools: ['pwntools fmtstr_payload'],
        codeSnippet: \`writes = {got_printf: system_addr}
payload = fmtstr_payload(offset, writes)
p.sendline(payload)\`
      }
    ],
    
    postconditions: {
      successIndicators: ['Memory leaked successfully', 'GOT overwritten'],
      artifacts: ['Leaked values']
    },
    
    operatorChecklist: [
      '[ ] Verify format string works',
      '[ ] Find exact input offset on stack',
      '[ ] Check RELRO (Partial/No RELRO required for GOT overwrite)'
    ],
    
    vulnerabilityTypes: ['CWE-134', 'Format String'],
    
    references: []
  },`;

const heapReplacement = `  heap_buffer_overflow: {
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
        '1. GDB: \`heap\` or \`vis\` to view chunks',
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
        codeSnippet: \`malloc(0x20) # chunk A
free(chunk_A)
# Overflow/UAF write chunk_A->fd with target_addr
malloc(0x20) # returns chunk_A
malloc(0x20) # returns target_addr!\`
      }
    ],
    
    postconditions: {
      successIndicators: ['Arbitrary allocation achieved', 'Heap state successfully modified'],
      artifacts: ['Heap visualization log']
    },
    
    operatorChecklist: [
      '[ ] Determine glibc version (crucial for heap techniques)',
      '[ ] Check if Safe Linking XOR protection is enabled (glibc >= 2.32)',
      '[ ] Keep heap layout clean and aligned'
    ],
    
    vulnerabilityTypes: ['CWE-122', 'Heap Overflow'],
    references: []
  },`;

// Replace using regex properly
const formatRegex = /  format_string_vulnerability: \{[\s\S]*?vulnerabilityTypes: \['format'\],\n\n    references: \[\n      \{ tool: 'pwntools', description: 'fmtstr_payload for automated FSB exploitation' \},\n      \{ description: 'Format String Attack - Wikipedia', url: 'https:\/\/en\.wikipedia\.org\/wiki\/Printf_format_string_attack' \},\n      \{ description: 'Format String Vulnerability Exploitation', url: 'https:\/\/ctf101\.org\/binary-exploitation\/format-string\/' \}\n    \]\n  \},/g;
const heapRegex = /  heap_buffer_overflow: \{[\s\S]*?vulnerabilityTypes: \['heap'\],\n    \n    references: \[\n      \{ tool: 'how2heap', description: 'Heap exploitation techniques repository', url: 'https:\/\/github\.com\/shellphish\/how2heap' \},\n      \{ tool: 'pwndbg', description: 'heap command for visualizing malloc structures' \},\n      \{ description: 'Heap Exploitation CTF101', url: 'https:\/\/ctf101\.org\/binary-exploitation\/heap\/' \}\n    \]\n  \},/g;

let matchesF = content.match(formatRegex);
if(matchesF) {
  content = content.replace(formatRegex, formatReplacement);
  console.log("Replaced Format String!");
} else {
  console.log("Format String regex did not match!");
}

let matchesH = content.match(heapRegex);
if(matchesH) {
  content = content.replace(heapRegex, heapReplacement);
  console.log("Replaced Heap Overflow!");
} else {
  console.log("Heap Overflow regex did not match!");
}

fs.writeFileSync('lib/pwn-knowledge-base.ts', content);

