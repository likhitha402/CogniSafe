/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        cyber: {
          dark: '#0a0f1c',
          cyan: '#00f2ff',
          alert: '#ff0055',
          gold: '#f2ff00',
        }
      }
    },
  },
  plugins: [],
}