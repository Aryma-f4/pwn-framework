# PWN Exploitation Decision Tree - Interactive Dashboard

A comprehensive, interactive cyberpunk-themed decision tree for binary exploitation techniques and vulnerability analysis. Built with React, D3.js, Next.js, and Tailwind CSS.

**Knowledge Base by**: [Aryma-f4/pwn-framework](https://github.com/Aryma-f4/pwn-framework)  
**Data Source**: Master Binary Exploitation Decision & Knowledge Matrix v5.0

## Architecture Overview

```mermaid
flowchart TB
    subgraph Client["Frontend - Next.js 16"]
        A["app/page.tsx<br/>Main Dashboard"] --> B["PwnTreeCanvas<br/>D3.js Tree Visualization"]
        A --> C["PwnSidebar<br/>Search & Filters"]
        A --> D["PwnInspector<br/>Technique Details"]
        A --> E["KeyboardShortcuts<br/>Global Hotkeys"]
    end

    subgraph Data["lib/ - Data Layer"]
        F["pwn-data.ts<br/>Technique Tree Structure"]
        G["pwn-knowledge-base.ts<br/>Detailed Exploitation KB"]
        H["pwn-unified-data.ts<br/>KB Mapping"]
        I["pwn-filters.ts<br/>Filter Logic"]
        J["pwn-recon-data.ts<br/>Recon Recommendations"]
        K["d3-utils.ts<br/>Tree Layout & Rendering"]
    end

    B --> F
    B --> K
    C --> I
    C --> F
    D --> F
    D --> H
    D --> G

    style Client fill:#1a1a2e,color:#fff
    style Data fill:#16213e,color:#00d9ff
```

## Data Flow

```mermaid
sequenceDiagram
    participant User
    participant Dashboard as app/page.tsx
    participant Sidebar as PwnSidebar
    participant Canvas as PwnTreeCanvas
    participant Inspector as PwnInspector
    participant Data as lib/pwn-data.ts

    User->>Dashboard: Select technique
    Dashboard->>Sidebar: Update search/filter state
    Dashboard->>Canvas: Render filtered tree
    Canvas->>Data: Fetch PWN_TECHNIQUES
    User->>Sidebar: Apply filter (stack/heap/format/sandbox)
    Sidebar->>Dashboard: Update activeFilter
    Dashboard->>Canvas: Re-render with filteredTechniques
    User->>Canvas: Click node
    Canvas->>Dashboard: onNodeSelect(technique)
    Dashboard->>Inspector: Show technique details
    Inspector->>Data: Lookup technique
    Inspector->>Inspector: Display blueprint + prerequisites
```

## Exploitation Tree Structure

```mermaid
flowchart TB
    ROOT["PWN Journey<br/>root"]
    
    ROOT --> SETUP["Setup & Prerequisites<br/>setup_tools_root"]
    ROOT --> PREREQ["Prerequisites<br/>prerequisites_root"]
    ROOT --> TOOLS["Core Tools<br/>tools_root"]
    ROOT --> EXPLOIT["Exploitation Tree<br/>exploitation_root"]
    ROOT --> MITIG["Binary Protections<br/>mitigations_root"]
    ROOT --> RECON["Reconnaissance<br/>recon_tools_root"]

    EXPLOIT --> BO["Buffer Overflow<br/>buffer_overflow"]
    EXPLOIT --> FS["Format String<br/>format_string"]
    EXPLOIT --> HEAP["Heap Exploit<br/>heap_exploit"]
    EXPLOIT --> SANDBOX["Sandbox Escape<br/>sandbox_escape"]
    EXPLOIT --> FSOP["FSOP Exploit<br/>fsop_exploit"]
    EXPLOIT --> INT["Integer Exploits<br/>integer_exploits"]

    BO --> STACK_PIVOT["Stack Pivot<br/>stack_pivot"]
    BO --> ROP["ROP Chain<br/>rop_chain"]
    BO --> RET2CSU["ret2csu<br/>ret2csu"]
    BO --> RET2DLRESOLVE["ret2dlresolve<br/>ret2dlresolve"]
    BO --> SROP["SROP<br/>srop"]
    BO --> STACK_CLASH["Stack Clash<br/>stack_clash"]
    BO --> BROP["BROP<br/>brop"]
    BO --> JOP["JOP<br/>jop"]
    BO --> RET2VDSO["ret2vdso<br/>ret2vdso"]

    ROP --> ROP_EXEC["rop_exec<br/>leaf"]

    FS --> FORMAT_LEAK["format_leak<br/>format_leak"]
    FS --> FORMAT_WRITE["format_write<br/>format_write"]
    FS --> GOT_OVERWRITE["got_overwrite<br/>got_overwrite"]

    HEAP --> UAF["Use After Free<br/>use_after_free"]
    HEAP --> DOUBLE_FREE["double_free<br/>double_free"]
    HEAP --> VTABLE["vtable Hijack<br/>vtable_hijack"]
    HEAP --> HEAP_CONTROL["heap_control<br/>heap_control"]
    HEAP --> HEAP_SPRAY["heap_spray<br/>heap_spray"]
    HEAP --> HOF["House of Force<br/>house_of_force"]
    HEAP --> HOS["House of Spirit<br/>house_of_spirit"]

    style ROOT fill:#00d9ff,color:#000
    style EXPLOIT fill:#a78bfa,color:#fff
    style BO fill:#10b981,color:#fff
    style FS fill:#f97316,color:#fff
    style HEAP fill:#ef4444,color:#fff
    style SANDBOX fill:#eab308,color:#000
```

## Mitigation Bypass Tree

```mermaid
flowchart TB
    MITIGS["Binary Protections"]

    MITIGS --> ASLR["ASLR / PIE<br/>aslr_prot"]
    MITIGS --> NX["NX (No-Execute)<br/>nx_prot"]
    MITIGS --> CANARY["Stack Canaries<br/>canary_prot"]
    MITIGS --> RELRO["RELRO<br/>relro_prot"]

    ASLR --> INFO_LEAK["Information Leak<br/>info_leak_bypass"]
    ASLR --> PARTIAL["Partial Overwrite<br/>partial_overwrite"]

    NX --> ROP_BYPASS["Code Reuse (ROP)<br/>rop_bypass"]

    CANARY --> CANARY_LEAK["Canary Leak<br/>canary_leak"]
    CANARY --> CANARY_BRUTE["Canary Bruteforce<br/>canary_bruteforce"]

    RELRO --> HOOK_OVERWRITE["Hook Overwrite / FSOP<br/>relro_bypass"]

    style ASLR fill:#f97316,color:#fff
    style NX fill:#f97316,color:#fff
    style CANARY fill:#f97316,color:#fff
    style RELRO fill:#f97316,color:#fff
```

## Exploitation Decision Flow (Bypass Path)

```mermaid
flowchart LR
    subgraph Analyze["1. Analyze Binary"]
        A1["checksec<br/>NX/PIE/Canary/RELRO"] --> A2["Identify mitigations"]
    end

    subgraph Bypass["2. Bypass Mitigations"]
        A2 --> B1{"NX enabled?"}
        B1 -- YES --> B2["Use ROP / Code Reuse"]
        B1 -- NO --> B3["Execute shellcode directly"]
        
        A2 --> C1{"PIE enabled?"}
        C1 -- YES --> C2["Leak libc address<br/>info_leak_bypass"]
        C1 -- NO --> C3["Use fixed addresses"]
        
        A2 --> D1{"Canary enabled?"}
        D1 -- YES --> D2["Leak via fmtstr<br/>canary_leak"]
        D2 --> D3["Bruteforce byte-by-byte<br/>canary_bruteforce"]
    end

    subgraph Exploit["3. Exploitation Technique"]
        B2 --> E1["ret2libc"]
        B2 --> E2["ret2plt"]
        B2 --> E3["SROP"]
        B2 --> E4["JOP/BROP"]
        
        C2 --> E1
    end

    subgraph Pwn["4. Get Shell"]
        E1 --> P1["system('/bin/sh')"]
        E2 --> P1
        E3 --> P1
        E4 --> P1
    end

    style Analyze fill:#16213e,color:#00d9ff
    style Bypass fill:#1a1a2e,color:#eab308
    style Exploit fill:#16213e,color:#10b981
    style Pwn fill:#0f3460,color:#ef4444
```

## Heap Exploitation Family

```mermaid
flowchart TB
    HEAP["Heap Exploitation<br/>heap_exploit"]
    
    HEAP --> UAF["Use After Free<br/>use_after_free"]
    HEAP --> DOUBLE_FREE["double_free<br/>double_free"]
    HEAP --> CHUNK_OVERFLOW["chunk_overflow<br/>heap_exploit"]
    HEAP --> VTABLE["vtable_hijack<br/>vtable_hijack"]
    HEAP --> HOUSE["House of X<br/>house_of_force"]

    UAF --> UAF_GL["UAF + House of Spirit<br/>house_of_spirit"]
    UAF --> UAF_TCache["UAF + Tcache Poisoning<br/>use_after_free_detailed"]

    DOUBLE_FREE --> FASTBIN_DUP["fastbin_dup<br/>heap_buffer_overflow"]
    DOUBLE_FREE --> TCACHE_DUP["tcache_poisoning<br/>heap_buffer_overflow"]

    HOUSE --> HOF["House of Force<br/>house_of_force"]
    HOUSE --> HOS["House of Spirit<br/>house_of_spirit"]
    HOUSE --> HOE["House of Einherjar<br/>heap_buffer_overflow"]
    HOUSE --> HOC["House of Corrosion<br/>heap_buffer_overflow"]

    style HEAP fill:#ef4444,color:#fff
    style UAF fill:#991b1b,color:#fff
    style DOUBLE_FREE fill:#991b1b,color:#fff
    style HOUSE fill:#7f1d1d,color:#fff
```

## Reconnaissance Workflow

```mermaid
flowchart TB
    START["Binary Analysis"] --> FILE["$ file ./target"]
    
    FILE --> CHECKSEC{"checksec --file=./target"}
    CHECKSEC --> |"NX=disabled"| NX_OFF["Execute shellcode directly"]
    CHECKSEC --> |"NX=enabled"| NX_ON["Use ROP techniques"]
    
    CHECKSEC --> |"PIE=enabled"| PIE_ON["Need information leak"]
    CHECKSEC --> |"PIE=disabled"| PIE_OFF["Use fixed addresses"]
    
    CHECKSEC --> |"Canary=enabled"| CANARY_ON["Leak or bruteforce canary"]
    CHECKSEC --> |"Canary=disabled"| CANARY_OFF["Direct stack overflow"]
    
    NX_ON --> FIND_ROP{"Find ROP gadgets<br/>ROPgadget / ropper"}
    PIE_ON --> LEAK["Trigger OOB/format leak"]
    LEAK --> CALC["Calculate libc base"]
    CANARY_ON --> LEAK

    FIND_ROP --> BUILD_CHAIN["Build ROP chain"]
    CALC --> BUILD_CHAIN
    BUILD_CHAIN --> SHELL["pwn()</i><li>system('/bin/sh')</li></ul>"]
    
    style START fill:#00d9ff,color:#000
    style NX_ON fill:#f97316,color:#fff
    style PIE_ON fill:#f97316,color:#fff
    style CANARY_ON fill:#eab308,color:#000
    style SHELL fill:#10b981,color:#fff
```

## Reconnaissance Tools

```mermaid
flowchart TB
    RECON["Reconnaissance<br/>recon_tools_root"]
    
    RECON --> STATIC["static_analysis<br/>Static Analysis"]
    RECON --> DYNAMIC["dynamic_analysis<br/>Dynamic Analysis"]

    STATIC --> STRINGS["strings -n 8 ./target"]
    STATIC --> READELF["readelf -s ./target"]
    STATIC --> OBJDUMP["objdump -M intel -d ./target"]
    STATIC --> GHIDRA["Ghidra / IDA Pro"]
    STATIC --> RADARE2["radare2"]

    DYNAMIC --> STRACE["strace -i -v ./target"]
    DYNAMIC --> LTRACE["ltrace ./target"]
    DYNAMIC --> GDB["gdb ./target"]
    DYNAMIC --> PWNDBG["pwndbg / GEF"]
    DYNAMIC --> CYCLIC["cyclic 200<br/>pattern offset finding"]

    style RECON fill:#10b981,color:#fff
    style STATIC fill:#16213e,color:#00d9ff
    style DYNAMIC fill:#16213e,color:#00d9ff
```

## Component Hierarchy

```mermaid
flowchart TB
    APP["app/page.tsx<br/>PwnExploitationDashboard"]
    
    APP --> HEADER["pwn-header<br/>Logo + Actions"]
    APP --> SIDEBAR["PwnSidebar<br/>Search/Filters/Phases"]
    APP --> CANVAS["PwnTreeCanvas<br/>D3.js Tree"]
    APP --> INSPECTOR["PwnInspector<br/>Details Panel"]
    APP --> FOOTER["pwn-footer<br/>Attribution"]

    SIDEBAR --> SEARCH["SearchInput<br/>Real-time search"]
    SIDEBAR --> FILTERS["Vulnerability Filters<br/>stack/format/heap/sandbox"]
    SIDEBAR --> PHASES["Phase Tracking<br/>recon/bypass/exploit/execute"]
    SIDEBAR --> PINNED["Pinned Techniques<br/>Ctrl+P"]

    INSPECTOR --> DETAILS["TechniqueDetails<br/>blueprint/prerequisites"]
    INSPECTOR --> PRECONDITIONS["Preconditions<br/>stack/format/heap/sandbox tags"]
    INSPECTOR --> EXPLOIT_PATHS["Exploitation Paths<br/>multiple strategies"]
    INSPECTOR --> CHECKLIST["Operator Checklist<br/>step-by-step"]
    INSPECTOR --> REFERENCES["References<br/>tools + writeups"]

    CANVAS --> ZOOM["ZoomControls<br/>+/reset/-"]
    CANVAS --> NODES["TreeNodes<br/>colored by category"]
    CANVAS --> LINKS["Cubic Bezier Links<br/>animated"]

    style APP fill:#1a1a2e,color:#fff
    style SIDEBAR fill:#16213e,color:#00d9ff
    style CANVAS fill:#16213e,color:#10b981
    style INSPECTOR fill:#16213e,color:#a78bfa
```

## Features

### Interactive Visualization
- **D3.js Hierarchical Tree**: Real-time interactive tree layout with zoom/pan controls
- **Color-Coded Nodes**: Visual categorization by vulnerability type:
  - 🟦 Cyan: `root` - Entry points
  - 🟩 Lime: `recon` - Reconnaissance techniques
  - 🟪 Purple: `technique` - Intermediate techniques
  - 🟧 Orange: `mitigation` - Mitigation bypasses
  - 🟥 Red: `leaf` - Terminal exploitation techniques
- **Smooth Animations**: Cubic bezier link paths with transition effects
- **Node Selection**: Click any node to inspect detailed information

### Search & Discovery
- **Real-Time Search**: Find techniques by name with instant highlighting
- **Path Highlighting**: Visualize parent-child relationships for matched nodes
- **Quick Filters**: Pre-built filters for vulnerability types:
  - **Stack-based**: Buffer overflows and ROP exploits
  - **Format Strings**: Printf vulnerabilities and format string attacks
  - **Heap-based**: Heap corruption and UAF exploits
  - **Sandbox Escape**: Container and browser breakouts

### Comprehensive Knowledge Base
Each technique includes:

#### **Preconditions**
- Detailed summary of vulnerability requirements
- List of necessary conditions for exploitation
- Step-by-step detection and analysis procedures
- Offset discovery methods (pwntools, pwndbg, GEF, PEDA)

#### **Exploitation Paths**
Multiple exploitation strategies with:
- Detailed step-by-step instructions
- Required tools and utilities
- Code snippets with copy-to-clipboard functionality
- Applicable libc versions and environment requirements

#### **Operator Checklist**
Complete workflow checklist for:
- Protection analysis
- Vulnerability detection
- Gadget hunting and chain building
- Local and remote testing

#### **References**
- Tool documentation links
- External write-ups and tutorials
- GitHub repositories
- CTF challenge references

### Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `/` | Focus search input |
| `Esc` | Clear selection / close mobile overlay |
| `?` | Show keyboard help modal |
| `Ctrl+P` | Pin/unpin selected technique |

## Technical Stack

- **Framework**: Next.js 16 (App Router)
- **Visualization**: D3.js (pure, no reactwrapper)
- **Styling**: Tailwind CSS v4 + Custom Cyberpunk CSS
- **Language**: TypeScript
- **Icons**: Lucide React
- **Components**: shadcn/ui

## Covered Exploitation Techniques

### Stack-Based Buffer Overflow (SBOF)
- **Paths**: ret2shellcode, ret2libc, ret2plt, ret2syscall/SROP
- **Tools**: ROPgadget, pwntools, one_gadget, libc-database
- **Protections**: Canary bypass, ASLR defeat, NX mitigation

### Format String Vulnerability (FSB)
- **Paths**: Arbitrary read, arbitrary write, canary leak + SBOF
- **Techniques**: %n/%hn/%hhn writes, stack leaking, GOT hijacking
- **Tools**: pwntools fmtstr_payload, manual crafting

### Heap Buffer Overflow
- **Paths**: fastbin dup, tcache poisoning, House of Force, unsorted bin attack
- **Techniques**: Chunk corruption, allocator manipulation, arbitrary write
- **Tools**: pwndbg heap commands, how2heap reference

### Sandbox / Seccomp Escape
- **Paths**: ORW (open/read/write) chain, seccomp filter bypass
- **Techniques**: Syscall gadget chaining, BPF filter analysis
- **Tools**: seccomp-tools, ROPgadget, ltrace/strace

## Core Tools Reference

Integrated knowledge base includes complete documentation for:
- **Binary Analysis**: checksec, readelf, objdump, file, nm
- **Debugging**: pwndbg, GEF, PEDA, GDB
- **ROP Gadgets**: ROPgadget, ropper, one_gadget
- **Exploitation**: pwntools, msfvenom
- **Dynamic Analysis**: strace, ltrace, radare2
- **Libc Lookup**: libc.rip, libc-database
- **Sandbox**: seccomp-tools

## Data Structure

### pwn-data.ts
Original technique tree structure with vulnerability type tagging

### pwn-knowledge-base.ts
Comprehensive knowledge base with:
- 4 major exploitation classes
- Preconditions and detection steps
- Multiple exploitation paths per technique
- Operator checklists
- Tool references

### pwn-unified-data.ts
Mapping layer connecting tree nodes with knowledge base entries

### d3-utils.ts
D3 visualization utilities:
- Hierarchy building with filtered techniques
- Tree layout calculations
- Color/opacity management by category
- Link path generation
- Node highlighting logic

## Keyboard Shortcuts & Interactions

- **Click Node**: Select and inspect technique details
- **Zoom**: Mouse wheel within canvas
- **Pan**: Drag canvas with mouse
- **Double-Click**: Reset zoom to full tree
- **Search**: Type to filter and highlight matching nodes
- **Filters**: Click preset filters to show vulnerability-type subsets

## Installation

### Prerequisites
- Node.js 18+ with pnpm

### Setup
```bash
# Install dependencies
pnpm install

# Run development server
pnpm dev

# Open browser to http://localhost:3000
```

### Deploy
```bash
# Deploy to Vercel (recommended)
vercel

# Or build for production
pnpm build
pnpm start
```

## API Routes & Data Flow

All data is client-side rendered. No backend required.

**Data Files**:
- `/lib/pwn-data.ts` - Tree structure
- `/lib/pwn-knowledge-base.ts` - KB entries
- `/lib/pwn-unified-data.ts` - Node-to-KB mapping
- `/lib/pwn-filters.ts` - Filter logic
- `/lib/d3-utils.ts` - Visualization helpers

## Styling

### Design System
- **Colors**: Cyberpunk dark palette (zinc-950, slate-900, slate-800)
- **Accents**: Cyan, Emerald, Amber, Rose (by category)
- **Glows**: Neon drop-shadows for depth
- **Fonts**: System fonts optimized for readability

### CSS Files
- `/styles/pwn-dashboard.css` - Main styles with neon effects
- `/app/globals.css` - Tailwind base configuration

## Contributing

This dashboard integrates the Master Binary Exploitation Decision Matrix from the **pwn-framework** project.

To contribute enhancements, exploits, or techniques:
- Fork: [github.com/Aryma-f4/pwn-framework](https://github.com/Aryma-f4/pwn-framework)
- Add techniques to the knowledge base
- Submit pull request with test cases
- Update reference links and write-ups

## Knowledge Base References

Each technique includes links to:
- **CTF101**: [ctf101.org/binary-exploitation](https://ctf101.org/binary-exploitation/)
- **how2heap**: [github.com/shellphish/how2heap](https://github.com/shellphish/how2heap)
- **pwntools Docs**: [docs.pwntools.com](https://docs.pwntools.com)
- **pwndbg**: [github.com/pwndbg/pwndbg](https://github.com/pwndbg/pwndbg)
- **seccomp-tools**: [github.com/david942j/seccomp-tools](https://github.com/david942j/seccomp-tools)
- **libc.rip**: Online libc symbol resolver
- **one_gadget**: [github.com/david942j/one_gadget](https://github.com/david942j/one_gadget)

## License

Knowledge base data sourced from public CTF resources and security research.  
Code licensed under MIT.

## Acknowledgments

- **Data Source**: Master Binary Exploitation Decision & Knowledge Matrix v5.0
- **Framework**: [Aryma-f4/pwn-framework](https://github.com/Aryma-f4/pwn-framework)
- **Inspiration**: CTF101, how2heap, pwntools documentation
- **Tools Referenced**: pwndbg, ROPgadget, seccomp-tools, and the broader security community