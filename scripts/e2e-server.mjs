import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createApp } from "../server/app.js";

const directory = mkdtempSync(resolve(tmpdir(), "archer-browser-test-"));
const root = fileURLToPath(new URL("../", import.meta.url));
const app = createApp({
  stateFile: resolve(directory, "state.json"),
  distDirectory: resolve(root, "dist"),
});
const server = app.listen(3102, "127.0.0.1", () =>
  console.log("Isolated Archer Security browser-test server ready."),
);
for (const signal of ["SIGINT", "SIGTERM"])
  process.on(signal, () => server.close(() => process.exit(0)));
process.on("exit", () => rmSync(directory, { recursive: true, force: true }));
