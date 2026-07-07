import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Static, dependency-light SPA. No backend; the gate evaluator is a client-side
// pure function. Base is relative so the build can be served from any subpath
// (e.g. wikigen.me/gate) or opened from a file host.
export default defineConfig({
  base: "./",
  plugins: [react()],
  build: {
    target: "es2021",
    sourcemap: true,
  },
});
