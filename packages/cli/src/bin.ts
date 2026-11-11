#!/usr/bin/env node
import { main } from "./cli.js";

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const c of process.stdin) {chunks.push(c as Buffer);}
  return Buffer.concat(chunks).toString("utf8");
}

const code = await main(
  process.argv.slice(2),
  {
    out: (s) => process.stdout.write(s),
    err: (s) => process.stderr.write(s),
    readStdin,
    isTTY: Boolean(process.stdin.isTTY),
  },
  {}
);
process.exitCode = code;
