/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        heading: ['"Space Grotesk"', 'sans-serif'],
        body: ['"IBM Plex Sans"', 'sans-serif'],
        mono: ['"IBM Plex Mono"', 'monospace']
      },
      colors: {
        ink: {
          900: '#0a1015',
          800: '#101c25',
          700: '#1a2b36'
        },
        pulse: {
          500: '#ff7a18',
          600: '#e66700'
        },
        signal: {
          500: '#2dd4bf',
          600: '#0ea5a0'
        }
      },
      boxShadow: {
        panel: '0 18px 40px -24px rgba(6, 24, 36, 0.85)'
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
