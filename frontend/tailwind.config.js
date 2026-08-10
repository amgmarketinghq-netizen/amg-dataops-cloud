/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class',
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        obsidian: '#080C14',
        slateDark: '#0B0F19',
        neonCyan: '#00F2FE',
        neonGreen: '#10B981',
        neonPurple: '#A855F7',
      },
    },
  },
  plugins: [],
}
