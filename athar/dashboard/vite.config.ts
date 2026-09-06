import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// base: "./" keeps the built bundle path-independent, so dist/index.html opens
// directly from the filesystem as well as from a served path.
export default defineConfig({
  plugins: [react()],
  base: "./",
});
