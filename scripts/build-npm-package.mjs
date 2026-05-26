#!/usr/bin/env node
import { execFileSync, spawnSync } from "node:child_process";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync
} from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(SCRIPT_DIR, "..");
const NPM_TEMPLATE_ROOT = path.join(REPO_ROOT, "npm");
const PACKAGE_NAME = "crebro";
const BINARY_BASENAME = "crebro";
const NPM_COMMAND = process.platform === "win32" ? "npm.cmd" : "npm";

const PLATFORM_PACKAGES = {
  "crebro-linux-x64": {
    alias: "crebro-linux-x64",
    tag: "linux-x64",
    targetTriple: "x86_64-unknown-linux-musl",
    os: "linux",
    cpu: "x64"
  },
  "crebro-linux-arm64": {
    alias: "crebro-linux-arm64",
    tag: "linux-arm64",
    targetTriple: "aarch64-unknown-linux-musl",
    os: "linux",
    cpu: "arm64"
  },
  "crebro-darwin-x64": {
    alias: "crebro-darwin-x64",
    tag: "darwin-x64",
    targetTriple: "x86_64-apple-darwin",
    os: "darwin",
    cpu: "x64"
  },
  "crebro-darwin-arm64": {
    alias: "crebro-darwin-arm64",
    tag: "darwin-arm64",
    targetTriple: "aarch64-apple-darwin",
    os: "darwin",
    cpu: "arm64"
  },
  "crebro-win32-x64": {
    alias: "crebro-win32-x64",
    tag: "win32-x64",
    targetTriple: "x86_64-pc-windows-msvc",
    os: "win32",
    cpu: "x64"
  },
  "crebro-win32-arm64": {
    alias: "crebro-win32-arm64",
    tag: "win32-arm64",
    targetTriple: "aarch64-pc-windows-msvc",
    os: "win32",
    cpu: "arm64"
  }
};

function usage() {
  console.log(`Usage: node scripts/build-npm-package.mjs [options]

Options:
  --package <name>          Package to stage: crebro, current, or a platform alias.
                            May be passed more than once.
  --release-version <ver>   Version to publish. Defaults to Cargo package version.
  --output-dir <dir>        Staging root. Defaults to dist/npm/stage.
  --pack-output-dir <dir>   Also run npm pack into this directory.
  --publish                 Run npm publish from each staged package.
  --dry-run                 Add --dry-run to npm publish.
  --otp <code>              Forward an npm OTP code to npm publish.
  --skip-build              Reuse target/release/crebro instead of building first.
  --help                    Show this help.
`);
}

function parseArgs(argv) {
  const args = {
    packages: [],
    releaseVersion: null,
    outputDir: path.join(REPO_ROOT, "dist", "npm", "stage"),
    packOutputDir: null,
    publish: false,
    dryRun: false,
    otp: null,
    skipBuild: false
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    switch (arg) {
      case "--package":
        args.packages.push(readOptionValue(argv, ++i, arg));
        break;
      case "--release-version":
        args.releaseVersion = readOptionValue(argv, ++i, arg);
        break;
      case "--output-dir":
        args.outputDir = path.resolve(REPO_ROOT, readOptionValue(argv, ++i, arg));
        break;
      case "--pack-output-dir":
        args.packOutputDir = path.resolve(REPO_ROOT, readOptionValue(argv, ++i, arg));
        break;
      case "--publish":
        args.publish = true;
        break;
      case "--dry-run":
        args.dryRun = true;
        break;
      case "--otp":
        args.otp = readOptionValue(argv, ++i, arg);
        break;
      case "--skip-build":
        args.skipBuild = true;
        break;
      case "--help":
      case "-h":
        usage();
        process.exit(0);
        break;
      default:
        throw new Error(`Unknown argument: ${arg}`);
    }
  }

  if (args.packages.length === 0) {
    args.packages.push(PACKAGE_NAME);
  }

  return args;
}

function readOptionValue(argv, index, option) {
  const value = argv[index];
  if (!value || value.startsWith("--")) {
    throw new Error(`${option} requires a value`);
  }
  return value;
}

function run(command, args, options = {}) {
  console.log(`+ ${[command, ...args].join(" ")}`);
  const result = spawnSync(command, args, {
    cwd: options.cwd ?? REPO_ROOT,
    env: options.env ?? process.env,
    encoding: "utf8",
    stdio: options.capture ? ["ignore", "pipe", "pipe"] : "inherit"
  });

  if (result.error) {
    throw new Error(`${command} ${args.join(" ")} failed: ${result.error.message}`);
  }

  if (result.status !== 0) {
    if (options.capture) {
      process.stdout.write(result.stdout ?? "");
      process.stderr.write(result.stderr ?? "");
    }
    throw new Error(`${command} ${args.join(" ")} failed with exit code ${result.status}`);
  }

  return result.stdout ?? "";
}

function readJson(filePath) {
  return JSON.parse(readFileSync(filePath, "utf8"));
}

function writeJson(filePath, value) {
  writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function cargoPackageVersion() {
  const metadata = JSON.parse(
    execFileSync("cargo", ["metadata", "--no-deps", "--format-version=1"], {
      cwd: REPO_ROOT,
      encoding: "utf8"
    })
  );
  const pkg = metadata.packages.find((item) => item.name === PACKAGE_NAME);
  if (!pkg) {
    throw new Error(`Unable to find Cargo package ${PACKAGE_NAME}`);
  }
  return pkg.version;
}

function rustHostTarget() {
  const verbose = execFileSync("rustc", ["-vV"], {
    cwd: REPO_ROOT,
    encoding: "utf8"
  });
  const hostLine = verbose
    .split("\n")
    .find((line) => line.startsWith("host: "));
  if (!hostLine) {
    throw new Error("Unable to determine rustc host target");
  }
  return hostLine.slice("host: ".length).trim();
}

function currentPlatformPackage() {
  const host = rustHostTarget();
  const packageKey = Object.keys(PLATFORM_PACKAGES).find(
    (key) => PLATFORM_PACKAGES[key].targetTriple === host
  );
  if (packageKey) {
    return packageKey;
  }

  if (host === "x86_64-unknown-linux-gnu") {
    return "crebro-linux-x64";
  }
  if (host === "aarch64-unknown-linux-gnu") {
    return "crebro-linux-arm64";
  }

  throw new Error(`Unsupported local Rust host target: ${host}`);
}

function expandPackages(packages) {
  const expanded = [];
  for (const requested of packages) {
    const packageKey = requested === "current" ? currentPlatformPackage() : requested;
    if (packageKey !== PACKAGE_NAME && !PLATFORM_PACKAGES[packageKey]) {
      throw new Error(`Unknown package '${requested}'`);
    }
    if (!expanded.includes(packageKey)) {
      expanded.push(packageKey);
    }
  }
  return expanded;
}

function copyCommonFiles(stagingDir) {
  for (const fileName of ["README.md", "LICENSE"]) {
    const src = path.join(REPO_ROOT, fileName);
    if (existsSync(src)) {
      copyFileSync(src, path.join(stagingDir, fileName));
    }
  }
}

function stageWrapper(stagingRoot, version) {
  const stagingDir = path.join(stagingRoot, `${PACKAGE_NAME}-${version}`);
  rmSync(stagingDir, { recursive: true, force: true });
  mkdirSync(path.join(stagingDir, "bin"), { recursive: true });

  copyFileSync(
    path.join(NPM_TEMPLATE_ROOT, "bin", "crebro.js"),
    path.join(stagingDir, "bin", "crebro.js")
  );
  chmodSync(path.join(stagingDir, "bin", "crebro.js"), 0o755);
  copyCommonFiles(stagingDir);

  const packageJson = readJson(path.join(NPM_TEMPLATE_ROOT, "package.json"));
  packageJson.version = version;
  packageJson.optionalDependencies = Object.fromEntries(
    Object.values(PLATFORM_PACKAGES).map((platformPackage) => [
      platformPackage.alias,
      `npm:${PACKAGE_NAME}@${version}-${platformPackage.tag}`
    ])
  );

  writeJson(path.join(stagingDir, "package.json"), packageJson);
  return { key: PACKAGE_NAME, stagingDir, version, tag: null };
}

function stagePlatformPackage(stagingRoot, version, packageKey, skipBuild) {
  const platformPackage = PLATFORM_PACKAGES[packageKey];
  const platformVersion = `${version}-${platformPackage.tag}`;
  const stagingDir = path.join(stagingRoot, `${PACKAGE_NAME}-${platformVersion}`);
  rmSync(stagingDir, { recursive: true, force: true });
  mkdirSync(stagingDir, { recursive: true });
  copyCommonFiles(stagingDir);

  if (!skipBuild) {
    const cargoArgs = ["build", "--release", "--locked", "--bin", BINARY_BASENAME];
    if (platformPackage.targetTriple !== rustHostTarget()) {
      cargoArgs.push("--target", platformPackage.targetTriple);
    }
    run("cargo", cargoArgs);
  }

  const binaryName = platformPackage.os === "win32" ? `${BINARY_BASENAME}.exe` : BINARY_BASENAME;
  const binarySrc =
    platformPackage.targetTriple === rustHostTarget()
      ? path.join(REPO_ROOT, "target", "release", binaryName)
      : path.join(REPO_ROOT, "target", platformPackage.targetTriple, "release", binaryName);
  if (!existsSync(binarySrc)) {
    throw new Error(`Expected release binary not found: ${binarySrc}`);
  }

  const binaryDestDir = path.join(
    stagingDir,
    "vendor",
    platformPackage.targetTriple,
    "bin"
  );
  mkdirSync(binaryDestDir, { recursive: true });
  const binaryDest = path.join(binaryDestDir, binaryName);
  copyFileSync(binarySrc, binaryDest);
  if (platformPackage.os !== "win32") {
    chmodSync(binaryDest, 0o755);
  }

  const template = readJson(path.join(NPM_TEMPLATE_ROOT, "package.json"));
  writeJson(path.join(stagingDir, "package.json"), {
    name: PACKAGE_NAME,
    version: platformVersion,
    description: `${template.description} Native binary for ${platformPackage.tag}.`,
    license: template.license,
    os: [platformPackage.os],
    cpu: [platformPackage.cpu],
    files: ["vendor"],
    repository: template.repository,
    engines: template.engines,
    keywords: template.keywords
  });

  return { key: packageKey, stagingDir, version: platformVersion, tag: platformPackage.tag };
}

function stagePackage(stagingRoot, version, packageKey, skipBuild) {
  if (packageKey === PACKAGE_NAME) {
    return stageWrapper(stagingRoot, version);
  }
  return stagePlatformPackage(stagingRoot, version, packageKey, skipBuild);
}

function packPackage(stagedPackage, packOutputDir) {
  mkdirSync(packOutputDir, { recursive: true });
  const stdout = run(
    NPM_COMMAND,
    ["pack", "--json", "--pack-destination", packOutputDir],
    { cwd: stagedPackage.stagingDir, capture: true }
  );

  let parsed;
  try {
    parsed = JSON.parse(stdout);
  } catch (error) {
    throw new Error(`Unable to parse npm pack JSON: ${error.message}\n${stdout}`);
  }

  const filename = parsed?.[0]?.filename;
  if (!filename) {
    throw new Error("npm pack did not report an output filename");
  }
  console.log(`Packed ${path.join(packOutputDir, filename)}`);
}

function publishPackage(stagedPackage, dryRun, otp) {
  const args = ["publish"];
  if (stagedPackage.tag) {
    args.push("--tag", stagedPackage.tag);
  }
  if (dryRun) {
    args.push("--dry-run");
  }
  if (otp) {
    args.push(`--otp=${otp}`);
  }
  run(NPM_COMMAND, args, { cwd: stagedPackage.stagingDir });
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const packages = expandPackages(args.packages);
  const version = args.releaseVersion ?? cargoPackageVersion();
  const stagingRoot = path.resolve(args.outputDir);

  if (args.dryRun && !args.publish) {
    throw new Error("--dry-run only applies with --publish");
  }

  mkdirSync(path.dirname(stagingRoot), { recursive: true });
  rmSync(stagingRoot, { recursive: true, force: true });
  mkdirSync(stagingRoot, { recursive: true });

  console.log(`Staging Crebro npm packages for version ${version}`);
  const stagedPackages = packages.map((packageKey) =>
    stagePackage(stagingRoot, version, packageKey, args.skipBuild)
  );

  for (const stagedPackage of stagedPackages) {
    console.log(`Staged ${stagedPackage.key}@${stagedPackage.version}`);
    console.log(`  ${path.relative(REPO_ROOT, stagedPackage.stagingDir)}`);
  }

  if (args.packOutputDir) {
    const packOutputDir = path.resolve(args.packOutputDir);
    for (const stagedPackage of stagedPackages) {
      packPackage(stagedPackage, packOutputDir);
    }
  }

  if (args.publish) {
    for (const stagedPackage of stagedPackages) {
      publishPackage(stagedPackage, args.dryRun, args.otp);
    }
  }
}

try {
  main();
} catch (error) {
  console.error(`error: ${error.message}`);
  process.exit(1);
}
