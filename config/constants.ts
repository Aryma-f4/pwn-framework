/**
 * Application constants
 * Centralized configuration values
 */

export const APP_CONSTANTS = {
  // Application info
  APP_NAME: 'PWN Framework',
  APP_VERSION: '1.0.0',
  APP_DESCRIPTION: 'Binary Exploitation Decision Tree',

  // Storage keys
  STORAGE_KEYS: {
    WELCOMED: 'pwn_welcomed',
    PINNED_TECHNIQUES: 'pwn_pinned_techniques',
    RECON_TAGS: 'pwn_recon_tags',
    CURRENT_PHASE: 'pwn_current_phase',
    COMPLETED_PHASES: 'pwn_completed_phases',
    SIDEBAR_STATE: 'pwn_sidebar_state',
    INSPECTOR_STATE: 'pwn_inspector_state',
  },

  // UI constants
  UI: {
    MOBILE_BREAKPOINT: 768,
    SIDEBAR_WIDTH_DESKTOP: 280,
    SIDEBAR_WIDTH_TABLET: 240,
    INSPECTOR_WIDTH_DESKTOP: 420,
    INSPECTOR_WIDTH_TABLET: 340,
    HEADER_HEIGHT: 52,
    FOOTER_HEIGHT: 32,
  },

  // Animation timings (in ms)
  ANIMATION: {
    FAST: 150,
    BASE: 300,
    SLOW: 500,
  },

  // Limits
  LIMITS: {
    MAX_LOGS: 100,
    MAX_PINNED_TECHNIQUES: 10,
    SEARCH_DEBOUNCE: 300,
    STORAGE_SIZE_WARNING: 5242880, // 5MB
  },

  // External links
  LINKS: {
    GITHUB_REPO: 'https://github.com/Aryma-f4/pwn-framework',
    CTF101: 'https://ctf101.org/binary-exploitation/',
    HOW2HEAP: 'https://github.com/shellphish/how2heap',
    PWNTOOLS_DOCS: 'https://docs.pwntools.com',
    PWNDBG: 'https://github.com/pwndbg/pwndbg',
    SECCOMP_TOOLS: 'https://github.com/david942j/seccomp-tools',
    LIBC_RIP: 'https://libc.rip',
    ONE_GADGET: 'https://github.com/david942j/one_gadget',
  },

  // Feature flags
  FEATURES: {
    ENABLE_ERROR_LOGGING: true,
    ENABLE_ANALYTICS: false,
    ENABLE_BETA_FEATURES: false,
  },
} as const;

export type AppConstants = typeof APP_CONSTANTS;
