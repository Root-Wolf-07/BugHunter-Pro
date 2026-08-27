/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        'bg-primary': '#0d1117',
        'bg-secondary': '#161b22',
        'bg-tertiary': '#21262d',
        'border-default': '#30363d',
        'text-primary': '#e6edf3',
        'text-secondary': '#8b949e',
        'accent-blue': '#58a6ff',
        'accent-cyan': '#39d353',
        'severity-critical': '#ff4757',
        'severity-high': '#ff6b35',
        'severity-medium': '#ffa502',
        'severity-low': '#2ed573',
        'severity-info': '#1e90ff',
      },
      fontFamily: {
        'mono': ['JetBrains Mono', 'Fira Code', 'Cascadia Code', 'monospace'],
        'sans': ['Inter', 'system-ui', 'sans-serif'],
      },
    },
  },
  plugins: [],
}

