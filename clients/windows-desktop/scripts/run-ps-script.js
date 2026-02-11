#!/usr/bin/env node

const { spawnSync } = require("node:child_process");
const path = require("node:path");

const script = process.argv[2];
const extraArgs = process.argv.slice(3);

if (!script) {
  console.error("Usage: node scripts/run-ps-script.js <script.ps1> [args...]");
  process.exit(2);
}

const scriptPath = path.resolve(process.cwd(), script);

const candidates = [
  { bin: "pwsh", args: ["-File", scriptPath, ...extraArgs] },
  {
    bin: "powershell",
    args: ["-ExecutionPolicy", "Bypass", "-File", scriptPath, ...extraArgs],
  },
];

let lastErr = null;

for (const candidate of candidates) {
  const result = spawnSync(candidate.bin, candidate.args, {
    stdio: "inherit",
    shell: false,
  });

  if (result.error) {
    if (result.error.code === "ENOENT") {
      lastErr = result.error;
      continue;
    }
    console.error(`Failed to run ${candidate.bin}: ${result.error.message}`);
    process.exit(1);
  }

  process.exit(result.status ?? 1);
}

console.error(
  `No PowerShell runtime found. Install PowerShell (pwsh) or use Windows PowerShell. Last error: ${lastErr?.message ?? "unknown"}`,
);
process.exit(127);
