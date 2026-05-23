/**
 * Workflow phases configuration
 * Centralized definition of all exploitation workflow phases
 */

export interface WorkflowPhase {
  id: string;
  label: string;
  description: string;
  keyActions: string[];
  tip: string;
}

export const WORKFLOW_PHASES: WorkflowPhase[] = [
  {
    id: 'recon',
    label: 'Recon',
    description: 'Analyze the binary — identify type, architecture, protections',
    keyActions: [
      'Run file ./binary',
      'Run checksec --file=./binary',
      'Run strings ./binary | grep -i flag',
      'Identify input vectors (stdin/argv/network)',
    ],
    tip: 'Start here! Understanding protections (NX, PIE, Canary, RELRO) determines your entire exploit path.',
  },
  {
    id: 'vuln',
    label: 'Vuln ID',
    description: 'Find the vulnerability — overflow, format string, UAF, etc.',
    keyActions: [
      'Run the binary with sample input',
      'Fuzz with cyclic pattern (pwntools cyclic)',
      'Check for format string (%p %x)',
      'Analyze in Ghidra/IDA for dangerous functions',
    ],
    tip: 'Use the Pre-Pwn Recon tab in the inspector to fill in what you find. It will auto-recommend exploit paths!',
  },
  {
    id: 'protect',
    label: 'Bypass',
    description: 'Bypass protections — ASLR, canary, NX, RELRO',
    keyActions: [
      'Identify which protections are enabled',
      'Find leak primitives for ASLR/PIE bypass',
      'Determine canary leak or bypass strategy',
      'Choose: GOT overwrite (Partial RELRO) or hook/FSOP (Full RELRO)',
    ],
    tip: 'Every protection has a bypass. The Pre-Pwn Recon recommends specific bypass strategies based on your findings.',
  },
  {
    id: 'exploit',
    label: 'Exploit',
    description: 'Choose and execute your exploit path',
    keyActions: [
      'Select exploit technique from recommendations',
      'Build ROP chain / craft payload',
      'Find gadgets with ROPgadget/ropper',
      'Write pwntools exploit script',
    ],
    tip: 'Click on a recommended exploit in the inspector to jump directly to the technique in the tree.',
  },
  {
    id: 'execute',
    label: 'Pwn',
    description: 'Test locally, then attack remote — get shell!',
    keyActions: [
      'Test exploit locally with ASLR disabled',
      'Debug in GDB/pwndbg — verify registers after crash',
      'Match remote libc version (libc.rip)',
      'Send exploit to remote target',
    ],
    tip: 'Always test locally first! Use patchelf/pwninit to set up the correct libc environment.',
  },
];
