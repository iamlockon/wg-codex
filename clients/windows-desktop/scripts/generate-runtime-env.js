#!/usr/bin/env node

const fs = require("fs");
const path = require("path");

const desktopRoot = path.resolve(__dirname, "..");
const outputPath = path.join(desktopRoot, "src-tauri", "app.env");
const sourceFiles = [
  path.join(desktopRoot, ".env"),
  path.join(desktopRoot, "ui", "src", ".env"),
];

const keys = [
  "ENTRY_API_BASE_URL",
  "VITE_GOOGLE_OIDC_CLIENT_ID",
  "VITE_GOOGLE_OIDC_REDIRECT_URI",
  "WG_WINDOWS_WIREGUARD_EXE",
  "WG_WINDOWS_CONFIG_DIR",
  "WG_WINDOWS_TUNNEL_NAME",
  "WG_WINDOWS_NOOP_TUNNEL",
  "WG_WINDOWS_CLIENT_STATE_FILE",
];

function parseEnvFile(content) {
  const out = {};
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const normalized = line.startsWith("export ") ? line.slice(7).trim() : line;
    const eq = normalized.indexOf("=");
    if (eq <= 0) continue;
    const key = normalized.slice(0, eq).trim();
    let value = normalized.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    if (key) out[key] = value;
  }
  return out;
}

const merged = {};

for (const file of sourceFiles) {
  if (!fs.existsSync(file)) continue;
  const content = fs.readFileSync(file, "utf8");
  Object.assign(merged, parseEnvFile(content));
}

for (const key of keys) {
  if (typeof process.env[key] === "string" && process.env[key].length > 0) {
    merged[key] = process.env[key];
  }
}

const lines = [];
for (const key of keys) {
  if (typeof merged[key] === "string" && merged[key].length > 0) {
    lines.push(`${key}=${merged[key]}`);
  }
}

fs.writeFileSync(outputPath, `${lines.join("\n")}\n`, "utf8");
console.log(`wrote ${outputPath} (${lines.length} keys)`);
