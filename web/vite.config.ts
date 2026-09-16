import { defineConfig } from "vite";
import solid from "vite-plugin-solid";

export default defineConfig({
  plugins: [solid()],
  server: { port: 5175 },
  // Keep the content hash and add an asset epoch so a poisoned or historically
  // incompatible immutable module cache can be retired across the whole graph.
  // `/assets/*` continues to cover this nested path in the Pages headers file.
  build: { target: "es2020", assetsDir: "assets/r2" },
});
