import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  root: "web",
  base: "./",
  plugins: [react()],
  worker: { format: "es" },
  server: { port: 5310, strictPort: true },
  build: { outDir: "../dist-web", emptyOutDir: true, target: "es2022" },
});
