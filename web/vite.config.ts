import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// macOS Seatbelt blocks FSEvents, so Codex previews need polling for HMR.
const isCodexSeatbeltSandbox = process.env.CODEX_SANDBOX === "seatbelt";

const apiProxy = {
  "/api": {
    target: "http://127.0.0.1:8776",
    changeOrigin: false,
  },
};

export default defineConfig({
  plugins: [react()],
  server: {
    host: "127.0.0.1",
    port: 8777,
    strictPort: true,
    proxy: apiProxy,
    ...(isCodexSeatbeltSandbox
      ? { watch: { useFsEvents: false, usePolling: true } }
      : {}),
  },
  preview: {
    host: "127.0.0.1",
    port: 8777,
    strictPort: true,
    proxy: apiProxy,
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
});
