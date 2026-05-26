#!/usr/bin/env node
import { spawn } from "node:child_process";
import { existsSync, realpathSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

const TARGET_BY_PLATFORM_ARCH = {
  "darwin:x64": "x86_64-apple-darwin",
  "darwin:arm64": "aarch64-apple-darwin",
  "linux:x64": "x86_64-unknown-linux-musl",
  "linux:arm64": "aarch64-unknown-linux-musl",
  "win32:x64": "x86_64-pc-windows-msvc",
  "win32:arm64": "aarch64-pc-windows-msvc"
};

const PLATFORM_PACKAGE_BY_TARGET = {
  "x86_64-unknown-linux-musl": "crebro-linux-x64",
  "aarch64-unknown-linux-musl": "crebro-linux-arm64",
  "x86_64-apple-darwin": "crebro-darwin-x64",
  "aarch64-apple-darwin": "crebro-darwin-arm64",
  "x86_64-pc-windows-msvc": "crebro-win32-x64",
  "aarch64-pc-windows-msvc": "crebro-win32-arm64"
};

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const require = createRequire(import.meta.url);

function fail(message) {
  console.error(`crebro: ${message}`);
  process.exit(1);
}

const targetTriple = TARGET_BY_PLATFORM_ARCH[`${process.platform}:${process.arch}`];
if (!targetTriple) {
  fail(`unsupported platform: ${process.platform} (${process.arch})`);
}

const platformPackage = PLATFORM_PACKAGE_BY_TARGET[targetTriple];
const crebroBinaryName = process.platform === "win32" ? "crebro.exe" : "crebro";

function resolveNativeBinary(vendorRoot) {
  const binaryPath = path.join(vendorRoot, targetTriple, "bin", crebroBinaryName);
  return existsSync(binaryPath) ? binaryPath : null;
}

let binaryPath = null;
try {
  const packageJsonPath = require.resolve(`${platformPackage}/package.json`);
  binaryPath = resolveNativeBinary(path.join(path.dirname(packageJsonPath), "vendor"));
} catch {
  binaryPath = null;
}

if (!binaryPath) {
  binaryPath = resolveNativeBinary(path.join(__dirname, "..", "vendor"));
}

if (!binaryPath) {
  fail(
    `missing optional dependency ${platformPackage}; reinstall with ` +
      "`npm install -g crebro@latest`"
  );
}

const env = {
  ...process.env,
  CREBRO_MANAGED_BY_NPM: "1",
  CREBRO_MANAGED_PACKAGE_ROOT: realpathSync(path.join(__dirname, ".."))
};

const child = spawn(binaryPath, process.argv.slice(2), {
  stdio: "inherit",
  env
});

child.on("error", (err) => {
  console.error(err);
  process.exit(1);
});

const forwardSignal = (signal) => {
  if (child.killed) {
    return;
  }
  try {
    child.kill(signal);
  } catch {
    /* ignore */
  }
};

["SIGINT", "SIGTERM", "SIGHUP"].forEach((signal) => {
  process.on(signal, () => forwardSignal(signal));
});

const childResult = await new Promise((resolve) => {
  child.on("exit", (code, signal) => {
    if (signal) {
      resolve({ type: "signal", signal });
    } else {
      resolve({ type: "code", exitCode: code ?? 1 });
    }
  });
});

if (childResult.type === "signal") {
  process.kill(process.pid, childResult.signal);
} else {
  process.exit(childResult.exitCode);
}
