// SPDX-License-Identifier: MIT
/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./app/dashboard/templates/**/*.html"],
  theme: {
    extend: {
      colors: {
        navy: {
          950: '#0a0e27',
          900: '#141b34',
          800: '#1e2849',
          700: '#283764',
          600: '#3d4f7c',
        },
        neon: {
          cyan: '#00d9ff',
          yellow: '#ffbe0b',
          green: '#06ffa5',
          pink: '#ff006e',
          blue: '#4cc9f0',
        },
      },
      fontFamily: {
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
      },
    },
  },
  plugins: [],
}
