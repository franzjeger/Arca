import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Tauri injects TAURI_DEV_HOST for mobile/remote dev; harmless on desktop.
const host = process.env.TAURI_DEV_HOST;

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  // Tauri expects a fixed dev port and owns the console output.
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    host: host || false,
    hmr: host ? { protocol: "ws", host, port: 1421 } : undefined,
    watch: {
      // Don't reload the frontend when Rust files change.
      ignored: ["**/src-tauri/**"],
    },
  },
  // Output to apps/desktop/dist, which tauri.conf.json references as ../dist.
  build: {
    outDir: "dist",
    emptyOutDir: true,
    target: "es2021",
  },
  // Component tests run in jsdom. The Tauri `invoke` bridge does not exist
  // there, so tests mock `../lib/api` rather than the transport.
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    include: ["src/**/*.test.{ts,tsx}"],
  },
});
