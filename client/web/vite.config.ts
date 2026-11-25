import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// The built app is served by notes-syncd at /app/ under a strict
// Content-Security-Policy, so the build must not need inline scripts, inline
// styles or data: URLs.
export default defineConfig({
  // Relative asset paths: the app works under any path prefix.
  base: "./",
  plugins: [react()],
  build: {
    target: "es2022",
    sourcemap: false,
    assetsInlineLimit: 0,
    modulePreload: { polyfill: false },
  },
  server: {
    // `npm run dev` next to a local notes-syncd (see README).
    proxy: {
      "/v1": "http://127.0.0.1:8443",
      "/healthz": "http://127.0.0.1:8443",
    },
  },
});
