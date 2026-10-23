import { createApp } from "./app.js";

const port = Number(process.env.PORT || 3001);
const host = process.env.HOST || "127.0.0.1";
if (!Number.isInteger(port) || port < 0 || port > 65535)
  throw new Error("PORT must be a valid TCP port.");
const server = createApp().listen(port, host, () => {
  console.log(
    `Archer Security demo server listening on ${host}:${server.address().port}`,
  );
});
server.on("error", (error) => {
  console.error(`Archer Security could not start: ${error.message}`);
  process.exitCode = 1;
});
for (const signal of ["SIGINT", "SIGTERM"])
  process.on(signal, () => server.close(() => process.exit(0)));
