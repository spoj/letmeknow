#!/usr/bin/env node

import { readFileSync, writeSync } from "node:fs";

if (process.argv[2] === "--skill") {
  if (process.argv.length !== 3) {
    process.stderr.write("Usage: npx letmeknow-cli --skill\n");
    process.exit(1);
  }
  writeSync(1, readFileSync(new URL("../SKILL.md", import.meta.url)));
} else if (process.env.LETMEKNOW_URL && process.argv.length === 2) {
  await import("./remote.js");
} else if (process.argv.slice(2).includes("--help") || process.argv.slice(2).includes("-h")) {
  process.stdout.write("Usage: npx letmeknow-cli [directory]\n\nServe a folder through the hosted LetMeKnow relay. The CLI does not listen on a network port. Form submissions are JSON lines on stdout.\n");
} else {
  try {
    await import("./relay.js");
  } catch (cause) {
    process.stderr.write(`letmeknow: ${cause instanceof Error ? cause.message : "server failed"}\n`);
    process.exitCode = 1;
  }
}
