/** @type {import('tailwindcss').Config} */
const withAlpha = (variable) => `rgb(var(${variable}) / <alpha-value>)`;

export default {
  darkMode: 'class',
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        heading: ['Montserrat', 'sans-serif'],
        body: ['Montserrat', 'sans-serif'],
        mono: ['"IBM Plex Mono"', 'monospace']
      },
      colors: {
        surface: {
          DEFAULT: withAlpha('--surface'),
          container: withAlpha('--surface-container'),
          'container-high': withAlpha('--surface-container-high'),
          lowest: withAlpha('--surface-lowest')
        },
        'on-surface': withAlpha('--on-surface'),
        muted: withAlpha('--on-surface-variant'),
        outline: {
          DEFAULT: withAlpha('--outline'),
          variant: withAlpha('--outline-variant')
        },
        primary: {
          DEFAULT: withAlpha('--primary'),
          container: withAlpha('--primary-container')
        },
        'on-primary': {
          DEFAULT: withAlpha('--on-primary'),
          container: withAlpha('--on-primary-container')
        },
        secondary: withAlpha('--secondary'),
        accent: withAlpha('--accent'),
        error: {
          DEFAULT: withAlpha('--error'),
          container: withAlpha('--error-container')
        },
        'on-error': withAlpha('--on-error'),
        success: withAlpha('--success'),
        warning: withAlpha('--warning'),
        info: withAlpha('--info'),
        sidebar: {
          DEFAULT: withAlpha('--sidebar-bg'),
          fg: withAlpha('--sidebar-fg'),
          muted: withAlpha('--sidebar-muted'),
          active: withAlpha('--sidebar-active')
        }
      },
      borderRadius: {
        sm: '0.25rem',
        DEFAULT: '0.5rem',
        md: '0.75rem',
        lg: '1rem',
        xl: '1.5rem',
        full: '9999px'
      },
      boxShadow: {
        soft: '0 1px 2px rgb(0 0 0 / 0.04), 0 8px 24px -16px rgb(0 0 0 / 0.12)'
      },
      keyframes: {
        rise: {
          '0%': { opacity: '0', transform: 'translateY(8px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' }
        }
      },
      animation: {
        rise: 'rise 0.35s ease forwards'
      }
    }
  },
  plugins: []
};
