#!/usr/bin/env node

const child_process = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const process = require("node:process");
const util = require("node:util");

function isMusl() {
  if (process.platform !== "linux") return false;
  // Node report header contains glibcVersionRuntime if built with glibc
  const report = typeof process.report?.getReport === "function" ? process.report.getReport() : null;
  if (report?.header?.glibcVersionRuntime) {
    return false;
  }
  // Check for alpine release or standard musl dynamic linkers
  if (fs.existsSync("/etc/alpine-release")) {
    return true;
  }
  try {
    const ldd = child_process.spawnSync("ldd", ["--version"], { encoding: "utf8" });
    if (ldd.stdout && ldd.stdout.includes("musl")) {
      return true;
    }
    if (ldd.stderr && ldd.stderr.includes("musl")) {
      return true;
    }
  } catch {
    // Ignore ldd probe failure
  }
  return false;
}

function getPlatformTarget() {
  const platform = process.platform;
  const arch = process.arch;

  if (platform === "linux") {
    const libc = isMusl() ? "musl" : "gnu";
    if (arch === "x64" || arch === "arm64") {
      return `linux-${arch}-${libc}`;
    }
  } else if (platform === "darwin") {
    if (arch === "x64" || arch === "arm64") {
      return `darwin-${arch}`;
    }
  } else if (platform === "win32") {
    if (arch === "x64" || arch === "arm64") {
      return `win32-${arch}`;
    }
  }

  return null;
}

const os = require("node:os");

function resolveBinaryPath() {
  if (process.env.BLUELINE_BINARY) {
    if (!path.isAbsolute(process.env.BLUELINE_BINARY)) {
      console.error(`BLUELINE_BINARY must be an absolute path (got '${process.env.BLUELINE_BINARY}').`);
      process.exit(1);
    }
    const override = path.resolve(process.env.BLUELINE_BINARY);
    if (fs.existsSync(override)) {
      return override;
    }
    console.error(`BLUELINE_BINARY is set to '${process.env.BLUELINE_BINARY}', but no file exists at that path.`);
    process.exit(1);
  }

  const target = getPlatformTarget();
  if (!target) {
    console.error(`Unsupported platform or architecture: ${process.platform} (${process.arch})`);
    console.error("You can compile and run directly via: cargo install blueline");
    process.exit(1);
  }

  const pkgName = `@blueline/binary-${target}`;
  const binName = process.platform === "win32" ? "blueline.exe" : "blueline";

  try {
    const pkgJsonPath = require.resolve(`${pkgName}/package.json`);
    const binPath = path.join(path.dirname(pkgJsonPath), binName);
    if (fs.existsSync(binPath)) {
      return binPath;
    }
  } catch {
    // Optional dependency resolution failed
  }

  console.error(`Failed to locate native blueline binary from package '${pkgName}'.`);
  console.error("This may happen if npm omitted optional dependencies during installation (e.g. npm/cli#4828).");
  console.error("\nTo resolve:");
  console.error("  1. Reinstall with optional dependencies: npm install -g @blueline/cli");
  console.error("  2. Or install directly from source: cargo install blueline");
  console.error("  3. Or set BLUELINE_BINARY=/path/to/blueline\n");
  process.exit(1);
}

function main() {
  const binPath = resolveBinaryPath();
  const args = process.argv.slice(2);

  const result = child_process.spawnSync(binPath, args, {
    stdio: "inherit",
    shell: false,
  });

  if (result.error) {
    console.error(`Failed to spawn blueline binary: ${result.error.message}`);
    process.exit(1);
  }

  if (result.signal) {
    if (typeof util.convertProcessSignalToExitCode === "function") {
      process.exit(util.convertProcessSignalToExitCode(result.signal));
    } else {
      const sigNum = os.constants.signals[result.signal] || 0;
      process.exit(128 + sigNum);
    }
  }

  process.exit(result.status ?? 0);
}

main();
