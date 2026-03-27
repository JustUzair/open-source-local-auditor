import { defineConfig } from "tsup";

export default defineConfig({
  entry: {
    web: "src/interfaces/web.ts",
    cli: "src/interfaces/cli.ts",
  },
  format: ["esm"],
  clean: true,
  minify: false,
  sourcemap: true,
  target: "es2022",
  shims: true,
});
