import { spawn } from "node:child_process";

const api = spawn(process.execPath, ["--watch", "server/index.js"], {
  stdio: "inherit",
});
const web = spawn(
  process.execPath,
  ["node_modules/vite/bin/vite.js", "--host", "0.0.0.0"],
  { stdio: "inherit" },
);
let stopping = false;
function stop(code = 0) {
  if (stopping) return;
  stopping = true;
  api.kill("SIGTERM");
  web.kill("SIGTERM");
  process.exitCode = code;
}
api.on("exit", (code) => stop(code ?? 1));
web.on("exit", (code) => stop(code ?? 1));
for (const signal of ["SIGTERM", "SIGINT"]) process.on(signal, () => stop(0));
