/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx,ts,tsx}"],
  theme: {
    extend: {
      colors: {
        surface: {
          DEFAULT: "#0f1117",
          1: "#161b22",
          2: "#1c2128",
          3: "#21262d",
          4: "#2d333b",
        },
        accent: {
          DEFAULT: "#58a6ff",
          green: "#3fb950",
          orange: "#d29922",
          red: "#f85149",
          purple: "#bc8cff",
        },
      },
      fontFamily: {
        mono: ["JetBrains Mono", "Fira Code", "monospace"],
      },
    },
  },
  plugins: [],
};
