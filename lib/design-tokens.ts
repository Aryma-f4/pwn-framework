/**
 * Design Tokens - Centralized configuration for all design values
 * Replaces magic numbers throughout the codebase
 */

export const DESIGN_TOKENS = {
  // Z-Index layers
  zIndex: {
    base: 0,
    dropdown: 100,
    sticky: 20,
    fixed: 30,
    modalBackdrop: 200,
    modal: 300,
    popover: 250,
    tooltip: 150,
    notification: 350,
  },

  // Spacing (in pixels)
  spacing: {
    xs: '0.25rem',    // 4px
    sm: '0.5rem',     // 8px
    md: '1rem',       // 16px
    lg: '1.5rem',     // 24px
    xl: '2rem',       // 32px
    '2xl': '2.5rem',  // 40px
    '3xl': '3rem',    // 48px
  },

  // Layout dimensions
  layout: {
    headerHeight: '52px',
    footerHeight: '32px',
    sidebarWidthDesktop: '280px',
    sidebarWidthTablet: '240px',
    inspectorWidthDesktop: '420px',
    inspectorWidthTablet: '340px',
    modalMaxWidth: '440px',
  },

  // Animation
  animation: {
    duration: {
      fast: '150ms',
      base: '300ms',
      slow: '500ms',
    },
    easing: {
      linear: 'linear',
      easeIn: 'cubic-bezier(0.4, 0, 1, 1)',
      easeOut: 'cubic-bezier(0, 0, 0.2, 1)',
      easeInOut: 'cubic-bezier(0.4, 0, 0.2, 1)',
    },
  },

  // Colors - Neon palette
  colors: {
    neon: {
      cyan: '#22d3ee',
      cyanDim: '#0891b2',
      magenta: '#f472b6',
      purple: '#a78bfa',
      lime: '#34d399',
      orange: '#fb923c',
      rose: '#fb7185',
    },

    // Surface colors
    surface: {
      0: '#080b12',      // Darkest background
      1: '#0f141e',
      2: '#161e2e',
      3: '#222e44',
      elevated: 'rgba(30, 41, 59, 0.7)',
    },

    // Text colors
    text: {
      primary: '#f8fafc',
      secondary: '#cbd5e1',
      muted: '#94a3b8',
      dim: '#64748b',
    },

    // Border colors
    border: {
      subtle: 'rgba(148, 163, 184, 0.1)',
      default: 'rgba(148, 163, 184, 0.18)',
      active: 'rgba(34, 211, 238, 0.4)',
    },

    // Status colors
    status: {
      success: '#34d399',
      warning: '#fb923c',
      error: '#fb7185',
      info: '#22d3ee',
    },
  },

  // Shadows and glows
  shadow: {
    sm: '0 1px 2px 0 rgba(0, 0, 0, 0.05)',
    md: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
    lg: '0 10px 15px -3px rgba(0, 0, 0, 0.1)',
    xl: '0 20px 25px -5px rgba(0, 0, 0, 0.1)',
    modal: '0 24px 48px rgba(0, 0, 0, 0.6), 0 0 60px rgba(34, 211, 238, 0.08)',
  },

  glow: {
    cyan: '0 0 15px rgba(34, 211, 238, 0.1)',
    magenta: '0 0 15px rgba(244, 114, 182, 0.1)',
    purple: '0 0 15px rgba(167, 139, 250, 0.1)',
  },

  // Border radius
  radius: {
    none: '0',
    sm: '0.375rem',    // 6px
    md: '0.5rem',      // 8px
    lg: '0.75rem',     // 12px
    xl: '1rem',        // 16px
    '2xl': '1.5rem',   // 24px
    full: '9999px',
  },

  // Typography
  typography: {
    fontSize: {
      xs: '0.75rem',     // 12px
      sm: '0.875rem',    // 14px
      base: '1rem',      // 16px
      lg: '1.125rem',    // 18px
      xl: '1.25rem',     // 20px
      '2xl': '1.5rem',   // 24px
      '3xl': '1.875rem', // 30px
    },
    fontWeight: {
      light: 300,
      normal: 400,
      medium: 500,
      semibold: 600,
      bold: 700,
    },
    lineHeight: {
      tight: 1.2,
      normal: 1.5,
      relaxed: 1.75,
    },
  },

  // Breakpoints
  breakpoints: {
    xs: '320px',
    sm: '640px',
    md: '768px',
    lg: '1024px',
    xl: '1280px',
    '2xl': '1536px',
  },

  // Transitions
  transition: {
    fast: 'all 150ms cubic-bezier(0.4, 0, 0.2, 1)',
    base: 'all 300ms cubic-bezier(0.4, 0, 0.2, 1)',
    slow: 'all 500ms cubic-bezier(0.4, 0, 0.2, 1)',
  },
} as const;

// Export type for TypeScript support
export type DesignTokens = typeof DESIGN_TOKENS;

// Helper function to get nested token values
export function getToken<T extends keyof DesignTokens>(
  category: T,
  key?: string
): DesignTokens[T] | string {
  if (!key) return DESIGN_TOKENS[category];
  return (DESIGN_TOKENS[category] as Record<string, any>)[key];
}
