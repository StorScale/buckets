import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// `npm run dev` proxies the API to a local consoled (CONSOLED_URL).
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: { "/api": process.env.CONSOLED_URL ?? "http://127.0.0.1:9090" },
  },
  build: { outDir: "dist", sourcemap: false },
});
