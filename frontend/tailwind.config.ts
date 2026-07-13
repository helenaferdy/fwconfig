import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        surface: {
          DEFAULT: "#000000",
          raised: "#0a0a0a",
          overlay: "#111111",
          border: "#2a2a2a",
          muted: "#444444",
        },
        ink: {
          DEFAULT: "#ffffff",
          muted: "#c8c8c8",
          dim: "#777777",
        },
        accent: {
          DEFAULT: "#ffffff",
          soft: "#1a1a1a",
          hover: "#e5e5e5",
        },
        success: "#ffffff",
        warning: "#dddddd",
        danger: "#ffffff",
      },
      fontFamily: {
        sans: [
          "var(--font-robot)",
          "ui-monospace",
          "SFMono-Regular",
          "Menlo",
          "Monaco",
          "Consolas",
          "monospace",
        ],
        mono: [
          "var(--font-robot)",
          "ui-monospace",
          "SFMono-Regular",
          "Menlo",
          "Monaco",
          "Consolas",
          "monospace",
        ],
      },
      boxShadow: {
        panel: "0 0 0 1px #222",
      },
    },
  },
  plugins: [],
};
export default config;
