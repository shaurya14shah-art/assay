import { defineConfig } from "vitest/config";

// Separate from vite.config.ts, whose root is web/ (the UI). Engine tests live in test/.
export default defineConfig({
  test: { root: ".", include: ["test/**/*.test.ts"] },
});
