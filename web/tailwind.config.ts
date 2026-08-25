import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: { DEFAULT: "#07080c", 900: "#070810", 800: "#0d0f16", 700: "#151823", 600: "#212636" },
        ember: { DEFAULT: "#ff6b2b", soft: "#ffb37a", deep: "#c93c00" },
        flame: "#ff3b30",
        gold: "#ffd166",
        acid: "#39d98a",
        matrix: "#00ff9c",
        sky: "#4aa8ff",
      },
      fontFamily: {
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "Consolas", "monospace"],
      },
      boxShadow: {
        glow: "0 0 24px rgba(255,107,43,0.28)",
        acidglow: "0 0 22px rgba(0,255,156,0.25)",
      },
      keyframes: {
        pulseline: { "0%,100%": { opacity: "0.4" }, "50%": { opacity: "1" } },
        scan: { "0%": { transform: "translateY(-100%)" }, "100%": { transform: "translateY(220%)" } },
        blink: { "0%,49%": { opacity: "1" }, "50%,100%": { opacity: "0" } },
        flow: { to: { strokeDashoffset: "-24" } },
        flicker: { "0%,100%": { opacity: "1" }, "92%": { opacity: "1" }, "94%": { opacity: "0.82" }, "96%": { opacity: "1" } },
      },
      animation: {
        pulseline: "pulseline 2s ease-in-out infinite",
        scan: "scan 3.2s linear infinite",
        blink: "blink 1.05s steps(1) infinite",
        flow: "flow 0.9s linear infinite",
        flicker: "flicker 6s linear infinite",
      },
    },
  },
  plugins: [],
};
export default config;
