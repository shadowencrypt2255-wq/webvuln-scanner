import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: "#0b0f14",
        surface: "#111826",
        surface2: "#0f1620",
        border: "#1f2937",
        muted: "#9ca3af",
        fg: "#e5e7eb",
        accent: "#38bdf8",
        crit: "#a21caf",
        high: "#dc2626",
        med: "#d97706",
        low: "#2563eb",
        info: "#6b7280",
        ok: "#16a34a",
      },
      fontFamily: {
        sans: ["ui-sans-serif", "system-ui", "Segoe UI", "Roboto", "Arial", "sans-serif"],
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
      },
    },
  },
  plugins: [],
};

export default config;
