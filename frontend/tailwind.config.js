/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        bg: "#0a0f14",
        panel: "#111823",
        border: "#1e2a38",
        accent: "#22d3ee",
      },
    },
  },
  plugins: [],
};
