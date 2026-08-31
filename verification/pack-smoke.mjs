import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const sourcePackage = JSON.parse(readFileSync(join(repoRoot, "package.json"), "utf8"));
const requiredFiles = [
  "package.json",
  "README.md",
  "LICENSE",
  "src/index.js",
  "src/index.d.ts",
  "bin/bay-verify",
  "test/index.test.mjs",
  "test/offline-verifier.test.mjs",
  "test/types.fixture.ts",
  "verification/verified-usage.mjs",
  "verification/pack-smoke.mjs",
  "skills/bay-run/SKILL.md",
];
const scriptRequirements = {
  check: ["src/index.js"],
  test: ["test/index.test.mjs", "test/offline-verifier.test.mjs"],
  "test:types": ["test/types.fixture.ts"],
  "test:smoke": ["verification/verified-usage.mjs"],
  "test:pack": ["verification/pack-smoke.mjs"],
};
const scriptsRunFromExtractedPackage = [
  "check",
  "test",
  "test:types",
  "test:smoke",
  "pack:dry-run",
];
const npmConfigPrefix = ["npm", "config"].join("_");
const npmEnvironment = {
  ...process.env,
  [`${npmConfigPrefix}_audit`]: "false",
  [`${npmConfigPrefix}_fund`]: "false",
  [`${npmConfigPrefix}_update_notifier`]: "false",
};

function run(command, args, cwd, label) {
  const result = spawnSync(command, args, {
    cwd,
    encoding: "utf8",
    env: npmEnvironment,
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.error) {
    throw new Error(`${label} could not start: ${result.error.message}`);
  }
  if (result.status !== 0) {
    const output = [result.stdout, result.stderr]
      .filter((value) => value)
      .join("\n")
      .trim();
    throw new Error(
      `${label} failed with exit ${result.status}${output ? `:\n${output.slice(-4_000)}` : ""}`,
    );
  }
  return result;
}

let tempRoot;
try {
  tempRoot = mkdtempSync(join(tmpdir(), "huggingbay-coprocessor-pack-"));
  const packDirectory = join(tempRoot, "pack");
  const extractDirectory = join(tempRoot, "extract");
  mkdirSync(packDirectory);
  mkdirSync(extractDirectory);

  const packOutput = run(
    "npm",
    [
      "pack",
      "--ignore-scripts",
      "--json",
      "--pack-destination",
      packDirectory,
    ],
    repoRoot,
    "source npm pack",
  );
  const packMetadata = JSON.parse(packOutput.stdout)[0];
  assert.equal(packMetadata.id, `${sourcePackage.name}@${sourcePackage.version}`);
  const packedFiles = new Set(packMetadata.files.map(({ path }) => path));
  for (const requiredFile of requiredFiles) {
    assert.ok(packedFiles.has(requiredFile), `packed artifact omits ${requiredFile}`);
  }
  for (const [scriptName, paths] of Object.entries(scriptRequirements)) {
    assert.equal(typeof sourcePackage.scripts?.[scriptName], "string", `missing ${scriptName} script`);
    for (const path of paths) {
      assert.ok(packedFiles.has(path), `${scriptName} needs omitted ${path}`);
    }
  }
  for (const dependencyField of [
    "dependencies",
    "optionalDependencies",
    "peerDependencies",
    "bundledDependencies",
  ]) {
    assert.deepEqual(
      sourcePackage[dependencyField] ?? (dependencyField === "bundledDependencies" ? [] : {}),
      dependencyField === "bundledDependencies" ? [] : {},
      `${dependencyField} must remain empty`,
    );
  }

  const tarballPath = join(packDirectory, packMetadata.filename);
  assert.ok(existsSync(tarballPath), "npm pack did not create the expected tarball");
  run("tar", ["-xzf", tarballPath, "-C", extractDirectory], tempRoot, "tarball extraction");

  const extractedRoot = join(extractDirectory, "package");
  assert.ok(existsSync(extractedRoot), "tarball did not extract a package directory");
  const extractedPackage = JSON.parse(readFileSync(join(extractedRoot, "package.json"), "utf8"));
  assert.equal(extractedPackage.version, sourcePackage.version);
  for (const [scriptName, paths] of Object.entries(scriptRequirements)) {
    for (const path of paths) {
      assert.ok(existsSync(join(extractedRoot, path)), `${scriptName} path is absent after extraction: ${path}`);
    }
  }

  run(
    "npm",
    ["install", "--ignore-scripts", "--no-audit", "--no-fund", "--package-lock=false"],
    extractedRoot,
    "packed npm install",
  );
  for (const scriptName of scriptsRunFromExtractedPackage) {
    run("npm", ["run", scriptName], extractedRoot, `packed npm run ${scriptName}`);
  }

  console.log(
    `Packed-artifact smoke passed: npm install and ${scriptsRunFromExtractedPackage.join(", ")} ran from extraction.`,
  );
} finally {
  if (tempRoot) rmSync(tempRoot, { force: true, recursive: true });
}
