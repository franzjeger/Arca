/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  // Theme is driven by CSS variables swapped on <html data-theme="…">; see
  // styles.css and src/lib/theme.ts. `darkMode: "class"` is kept for any Tailwind
  // `dark:` utilities, but the palette itself comes from the variables below so
  // existing `text-neutral-*`, `bg-panel`, etc. adapt without markup changes.
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        // Apple-Passwords-ish surfaces (values in styles.css, per theme).
        // canvas & accent are RGB triples so `/opacity` modifiers (e.g.
        // bg-accent/90, bg-canvas/80) still work; the rest have no opacity use.
        canvas: "rgb(var(--canvas-rgb) / <alpha-value>)",
        sidebar: "var(--sidebar)",
        panel: "var(--panel)",
        hairline: "var(--hairline)",
        accent: "rgb(var(--accent-rgb) / <alpha-value>)",
        // Theme-aware overlays: white-on-dark hover/hairline tints in dark mode,
        // black-on-light in light mode, so `bg-fill/5` / `ring-line/10` stay
        // visible in both. (Overlays on the accent-blue selection stay literal
        // white and are not routed here.)
        fill: "rgb(var(--fill-rgb) / <alpha-value>)",
        line: "rgb(var(--line-rgb) / <alpha-value>)",
        // Tailwind's neutral scale, remapped to variables. In dark mode these
        // match Tailwind's defaults (light-on-dark); in light mode they invert
        // by prominence so `text-neutral-100` stays the primary text color.
        neutral: {
          50: "var(--n-50)",
          100: "var(--n-100)",
          200: "var(--n-200)",
          300: "var(--n-300)",
          400: "var(--n-400)",
          500: "var(--n-500)",
          600: "var(--n-600)",
          700: "var(--n-700)",
          800: "var(--n-800)",
          900: "var(--n-900)",
        },
      },
      fontFamily: {
        sans: [
          "-apple-system",
          "BlinkMacSystemFont",
          "Segoe UI",
          "Inter",
          "system-ui",
          "sans-serif",
        ],
      },
    },
  },
  plugins: [],
};
