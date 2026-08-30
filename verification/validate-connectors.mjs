import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const expectedTools = ["coprocessor", "run_pin", "solve_task"];
const canonicalMcpUrl = "https://run.huggingbay.xyz/mcp/";
const privacyUrl = "https://run.huggingbay.xyz/privacy";
const dataPolicyUrl = "https://run.huggingbay.xyz/.well-known/data-policy.json";

function fail(message) {
  throw new Error(`connector validation failed: ${message}`);
}

function check(condition, message) {
  if (!condition) fail(message);
}

function readText(relativePath) {
  const filePath = resolve(repoRoot, relativePath);
  check(existsSync(filePath), `${relativePath} is missing`);
  return readFileSync(filePath, "utf8");
}

function readJson(relativePath) {
  try {
    return JSON.parse(readText(relativePath));
  } catch (error) {
    fail(`${relativePath} is not valid JSON (${error.message})`);
  }
}

function isRepoRelative(relativePath) {
  return (
    typeof relativePath === "string" &&
    relativePath.length > 0 &&
    !relativePath.startsWith("/") &&
    !/^[A-Za-z]:[\\/]/.test(relativePath) &&
    !relativePath.split(/[\\/]/).includes("..")
  );
}

function resolveWithinRepo(relativePath, label) {
  check(isRepoRelative(relativePath), `${label} must be a relative path without ..`);
  const target = resolve(repoRoot, relativePath);
  const outside = relative(repoRoot, target);
  check(outside === "" || (!outside.startsWith(`..${sep}`) && outside !== ".."), `${label} escapes the repository`);
  return target;
}

function resolvePluginAsset(pluginRoot, relativePath, label) {
  check(isRepoRelative(relativePath), `${label} must be a relative path without ..`);
  const target = resolve(pluginRoot, relativePath);
  const outside = relative(repoRoot, target);
  check(outside === "" || (!outside.startsWith(`..${sep}`) && outside !== ".."), `${label} escapes the repository`);
  return target;
}

function sameArray(actual, expected, label) {
  check(
    Array.isArray(actual) &&
      actual.length === expected.length &&
      actual.every((value, index) => value === expected[index]),
    `${label} must be exactly ${JSON.stringify(expected)}`,
  );
}

const marketplace = readJson(".cursor-plugin/marketplace.json");
check(marketplace.name === "huggingbay-connectors", "marketplace name is incorrect");
check(marketplace.owner?.name === "Hugging Bay", "marketplace owner is missing");
check(
  typeof marketplace.metadata?.description === "string" &&
    marketplace.metadata.description.includes("Bay Run"),
  "marketplace description must identify Bay Run",
);
check(Array.isArray(marketplace.plugins) && marketplace.plugins.length === 1, "marketplace must contain one plugin");

const entry = marketplace.plugins[0];
check(entry.name === "bay-run", "marketplace plugin name is incorrect");
check(
  typeof entry.description === "string" &&
    expectedTools.every((tool) => entry.description.includes(tool)),
  "marketplace plugin description must name all bounded tools",
);
const pluginRoot = resolveWithinRepo(entry.source, "marketplace plugin source");
const pluginManifestRelative = `${entry.source}/.cursor-plugin/plugin.json`;
const pluginManifest = readJson(pluginManifestRelative);
check(pluginManifest.name === "bay-run", "Cursor plugin manifest name is incorrect");
check(/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(pluginManifest.name), "Cursor plugin name is not lowercase kebab-case");
check(typeof pluginManifest.description === "string" && pluginManifest.description.length > 0, "Cursor plugin description is missing");
check(pluginManifest.description.includes("coprocessor"), "Cursor plugin description omits coprocessor");
check(pluginManifest.description.includes("run_pin"), "Cursor plugin description omits run_pin");
check(pluginManifest.description.includes("solve_task"), "Cursor plugin description omits solve_task");
check(pluginManifest.repository === "https://github.com/barneywohl/huggingbay-coprocessor", "Cursor plugin repository is incorrect");
check(pluginManifest.license === "MIT", "Cursor plugin license is missing");
check(typeof pluginManifest.mcpServers === "string", "Cursor plugin must point to an MCP config path");

const mcpConfigPath = resolvePluginAsset(pluginRoot, pluginManifest.mcpServers, "Cursor plugin MCP path");
check(existsSync(mcpConfigPath), "Cursor plugin MCP config is missing");
const mcpConfig = JSON.parse(readFileSync(mcpConfigPath, "utf8"));
check(Object.keys(mcpConfig).length === 1 && mcpConfig.mcpServers, "MCP config must contain only mcpServers");
check(Object.keys(mcpConfig.mcpServers).length === 1 && mcpConfig.mcpServers["bay-run"], "MCP config must contain only bay-run");
const server = mcpConfig.mcpServers["bay-run"];
check(Object.keys(server).length === 1 && server.url === canonicalMcpUrl, "MCP config must be URL-only and use the canonical public endpoint");

const grokConfig = readJson("connectors/grok-custom-connector.json");
sameArray(grokConfig.allowed_tools, expectedTools, "Grok allowed_tools");
check(grokConfig.server_url === canonicalMcpUrl, "Grok server_url is incorrect");
check(grokConfig.authorization === "$BAY_RUN_TOKEN", "Grok authorization must remain an environment placeholder");
check(!Object.keys(grokConfig.headers ?? {}).some((key) => key.toLowerCase() === "authorization"), "Grok headers must not contain a bearer credential");
check(grokConfig.server_description.includes("every supplied document"), "Grok description omits per-document Guarding");
check(grokConfig.server_description.includes("block > escalate > allow"), "Grok description omits Guard precedence");

const cursorInstall = readJson("connectors/cursor-install.json");
sameArray(cursorInstall.expected_tools, expectedTools, "Cursor expected_tools");
check(
  Object.keys(cursorInstall.config ?? {}).length === 1 &&
    cursorInstall.config.url === canonicalMcpUrl,
  "Cursor install config must be URL-only and use the canonical endpoint",
);
check(cursorInstall.config_base64 === Buffer.from(JSON.stringify(cursorInstall.config), "utf8").toString("base64"), "Cursor install payload does not match config");
check(cursorInstall.deeplink === `cursor://anysphere.cursor-deeplink/mcp/install?name=bay-run&config=${cursorInstall.config_base64}`, "Cursor deeplink does not match the documented install-link format");
check(cursorInstall.verification?.privacy === privacyUrl, "Cursor install privacy link is incorrect");
check(cursorInstall.verification?.data_policy === dataPolicyUrl, "Cursor install data-policy link is incorrect");

const cursorMcp = readJson("connectors/cursor-mcp.json");
const cursorServer = cursorMcp.mcpServers?.["bay-run"];
check(
  Object.keys(cursorServer ?? {}).length === 1 && cursorServer.url === canonicalMcpUrl,
  "Cursor MCP example must be URL-only and use the canonical endpoint",
);

const decisionPolicy = readJson("connectors/decision-policy.json");
sameArray(decisionPolicy.allowed_tools, expectedTools, "Decision policy allowed_tools");
check(decisionPolicy.failure_mode?.mode === "fail-closed", "Decision policy must fail closed");
check(decisionPolicy.failure_mode?.fail_open_configured === false, "Decision policy must not configure fail-open behavior");
check(decisionPolicy.privacy?.privacy_url === privacyUrl, "Decision policy privacy link is incorrect");
check(decisionPolicy.privacy?.data_policy_url === dataPolicyUrl, "Decision policy data-policy link is incorrect");
sameArray(
  decisionPolicy.coprocessor_contract?.document_precedence,
  ["block", "escalate", "allow"],
  "Coprocessor document precedence",
);
check(
  decisionPolicy.coprocessor_contract?.document_mapping?.includes("exact document_index"),
  "Decision policy omits exact document mapping",
);
check(
  decisionPolicy.coprocessor_contract?.rerank_gate?.includes("every Guard action is allow"),
  "Decision policy omits the all-allow rerank gate",
);

const readme = readText("README.md");
const security = readText("SECURITY.md");
const connectorDocs = [
  ["connectors/README.md", readText("connectors/README.md")],
  ["connectors/SUBMISSION.md", readText("connectors/SUBMISSION.md")],
  ["connectors/grok-custom-connector.md", readText("connectors/grok-custom-connector.md")],
  ["connectors/cursor-mcp.md", readText("connectors/cursor-mcp.md")],
];
check(readme.includes("This is the fail-closed policy."), "README fail-closed wording is missing");
check(readme.includes(privacyUrl), "README privacy link is missing");
check(readme.includes(dataPolicyUrl), "README data-policy link is missing");
for (const [path, contents] of connectorDocs) {
  check(contents.includes(privacyUrl), `${path} privacy link is missing`);
  check(contents.includes(dataPolicyUrl), `${path} data-policy link is missing`);
  check(/fail[- ]closed/i.test(contents), `${path} fail-closed wording is missing`);
}
check(readme.includes("every supplied document"), "README omits per-document Guarding");
check(readme.includes("block > escalate > allow"), "README omits Guard precedence");
check(readme.includes("high-risk action-safety"), "README omits action-safety escalation");
const contractConnectorDocs = connectorDocs.filter(
  ([path]) => path !== "connectors/SUBMISSION.md",
);
check(
  contractConnectorDocs.every(([, contents]) => contents.includes("document_guards")),
  "connector docs omit document Guard evidence mapping",
);
check(
  contractConnectorDocs.every(([, contents]) => contents.includes("block > escalate > allow")),
  "connector docs omit Guard precedence",
);
check(security.includes("fails closed by default"), "SECURITY.md fail-closed wording is missing");
check(/Never commit a bearer, API key, private key, or provider\s+credential/.test(security), "SECURITY.md credential-safety wording is missing");
check(readJson("package.json").version === "0.1.10", "package version must remain 0.1.10");

const trackedFiles = execFileSync("git", ["ls-files", "-co", "--exclude-standard", "-z"], { cwd: repoRoot })
  .toString("utf8")
  .split("\0")
  .filter(Boolean);
const absoluteLocalPath = new RegExp(`(?:^|[^A-Za-z0-9])\\/(?:${["Users", "Volumes"].join("|")})[\\\\/]`);
const fileUrl = `${"file"}:${"/".repeat(2)}`;
const liveSecret = /\b(?:sk|xai|ghp|github_pat|npm)_[A-Za-z0-9][A-Za-z0-9_-]{15,}\b/i;
const privateKey = /-----BEGIN(?: [A-Z]+)? PRIVATE KEY-----/;
for (const trackedFile of trackedFiles) {
  const contents = readText(trackedFile);
  check(!absoluteLocalPath.test(contents), `${trackedFile} contains an absolute local path`);
  check(!contents.includes(fileUrl), `${trackedFile} contains a file URL`);
  check(!liveSecret.test(contents), `${trackedFile} contains a likely live credential`);
  check(!privateKey.test(contents), `${trackedFile} contains private-key material`);
}

console.log(`Connector validation passed: Cursor marketplace shape, URL-only MCP, exact tool order, fail-closed wording, and ${trackedFiles.length} tracked-file secret/path checks.`);
