#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, "..");
const cargoToml = fs.readFileSync(path.join(rootDir, "Cargo.toml"), "utf8");
const versionMatch = cargoToml.match(/version\s*=\s*"([^"]+)"/);
if (!versionMatch) {
  throw new Error("Cannot find version in Cargo.toml");
}
const version = versionMatch[1];

const PLATFORMS = [
  { name: "linux-x64-gnu", os: "linux", cpu: "x64", libc: ["glibc"] },
  { name: "linux-x64-musl", os: "linux", cpu: "x64", libc: ["musl"] },
  { name: "linux-arm64-gnu", os: "linux", cpu: "arm64", libc: ["glibc"] },
  { name: "linux-arm64-musl", os: "linux", cpu: "arm64", libc: ["musl"] },
  { name: "darwin-x64", os: "darwin", cpu: "x64" },
  { name: "darwin-arm64", os: "darwin", cpu: "arm64" },
  { name: "win32-x64", os: "win32", cpu: "x64" },
  { name: "win32-arm64", os: "win32", cpu: "arm64" },
];

const packagesDir = path.join(rootDir, "packages");

for (const platform of PLATFORMS) {
  const pkgDir = path.join(packagesDir, `@blueline/binary-${platform.name}`);
  fs.mkdirSync(pkgDir, { recursive: true });

  const pkgJson = {
    name: `@blueline/binary-${platform.name}`,
    version,
    description: `Native blueline binary for ${platform.name}`,
    license: "MIT",
    os: [platform.os],
    cpu: [platform.cpu],
    ...(platform.libc ? { libc: platform.libc } : {}),
    preferUnplugged: true,
  };

  fs.writeFileSync(
    path.join(pkgDir, "package.json"),
    JSON.stringify(pkgJson, null, 2) + "\n"
  );
}

console.log(`Generated platform packages for version ${version}`);
