#!/usr/bin/env node
/**
 * axios-vuln-scanner
 * 
 * Scans a directory and all its subdirectories for projects affected by the
 * Axios npm Supply Chain Attack (March 31, 2026).
 *
 * Malicious versions: axios@1.14.1 and axios@0.30.4
 * Attack vector: Injected plain-crypto-js dependency with a RAT (Remote Access Trojan)
 * Affects: macOS, Windows, Linux
 *
 * References:
 *   - https://socket.dev/blog/axios-npm-package-compromised
 *   - https://ironplate.ai/blog/axios-npm-supply-chain-attack
 *   - https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan
 */

const fs = require("fs");
const path = require("path");
const os = require("os");

// ─── Constants ────────────────────────────────────────────────────────────────

const MALICIOUS_VERSIONS = ["1.14.1", "0.30.4"];

const SAFE_VERSIONS = {
  "1.x": "1.14.0",
  "0.x": "0.30.3",
};

const RAT_ARTIFACTS = {
  win32: [
    path.join(process.env.PROGRAMDATA || "C:\\ProgramData", "wt.exe"),
  ],
  darwin: ["/Library/Caches/com.apple.act.mond"],
  linux: ["/tmp/ld.py"],
};

const C2_DOMAIN = "sfrclak.com";
const C2_IP = "142.11.206.73";

const PHANTOM_PACKAGE = "plain-crypto-js";

const MALICIOUS_HASHES = {
  "axios@1.14.1": "d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71",
  "axios@0.30.4": "2553649f232204966871cea80a5d0d6adc700ca",
  "plain-crypto-js@4.2.1": "07d889e2dadce6f3910dcbc253317d28ca61c766",
};

// ─── ANSI Colors (works on all platforms with modern terminals) ───────────────

const NO_COLOR = process.env.NO_COLOR || !process.stdout.isTTY;

const c = {
  reset: NO_COLOR ? "" : "\x1b[0m",
  bold: NO_COLOR ? "" : "\x1b[1m",
  dim: NO_COLOR ? "" : "\x1b[2m",
  red: NO_COLOR ? "" : "\x1b[31m",
  green: NO_COLOR ? "" : "\x1b[32m",
  yellow: NO_COLOR ? "" : "\x1b[33m",
  cyan: NO_COLOR ? "" : "\x1b[36m",
  magenta: NO_COLOR ? "" : "\x1b[35m",
  white: NO_COLOR ? "" : "\x1b[37m",
  bgRed: NO_COLOR ? "" : "\x1b[41m",
  bgGreen: NO_COLOR ? "" : "\x1b[42m",
  bgYellow: NO_COLOR ? "" : "\x1b[43m",
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

function printBanner() {
  console.log(
    `${c.cyan}${c.bold}
╔══════════════════════════════════════════════════════════════╗
║         AXIOS SUPPLY CHAIN ATTACK — VULNERABILITY SCANNER   ║
║              Malicious versions: 1.14.1 / 0.30.4            ║
║                     March 31, 2026                          ║
╚══════════════════════════════════════════════════════════════╝${c.reset}`
  );
  console.log(
    `${c.dim}  References: socket.dev/blog/axios-npm-package-compromised${c.reset}\n`
  );
}

function printSection(title) {
  console.log(`\n${c.bold}${c.cyan}── ${title} ${"─".repeat(Math.max(0, 55 - title.length))}${c.reset}`);
}

function isMaliciousVersion(version) {
  if (!version) return false;
  const clean = version.replace(/^[\^~>=<v\s]+/, "").trim();
  return MALICIOUS_VERSIONS.includes(clean);
}

function fileExists(filePath) {
  try {
    fs.accessSync(filePath, fs.constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

function readJSON(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch {
    return null;
  }
}

function readText(filePath) {
  try {
    return fs.readFileSync(filePath, "utf8");
  } catch {
    return null;
  }
}

// ─── Lockfile parsers ─────────────────────────────────────────────────────────

function checkPackageLock(lockPath) {
  const lock = readJSON(lockPath);
  if (!lock) return [];

  const hits = [];

  // npm v2/v3 lockfile format
  const packages = lock.packages || {};
  for (const [pkgPath, info] of Object.entries(packages)) {
    if (pkgPath.endsWith("/axios") || pkgPath === "node_modules/axios") {
      if (isMaliciousVersion(info.version)) {
        hits.push({
          source: "package-lock.json (packages)",
          version: info.version,
          integrity: info.integrity || "N/A",
        });
      }
    }
    // Detect phantom dependency
    if (pkgPath.includes(PHANTOM_PACKAGE)) {
      hits.push({
        source: `package-lock.json — PHANTOM DEP ${c.red}${PHANTOM_PACKAGE}${c.reset} found!`,
        version: info.version || "unknown",
        integrity: info.integrity || "N/A",
        phantom: true,
      });
    }
  }

  // npm v1 legacy format
  const dependencies = lock.dependencies || {};
  function walkDeps(deps) {
    for (const [name, info] of Object.entries(deps)) {
      if (name === "axios" && isMaliciousVersion(info.version)) {
        hits.push({
          source: "package-lock.json (dependencies)",
          version: info.version,
          resolved: info.resolved || "N/A",
        });
      }
      if (name === PHANTOM_PACKAGE) {
        hits.push({
          source: `package-lock.json (dependencies) — PHANTOM DEP ${PHANTOM_PACKAGE}!`,
          version: info.version || "unknown",
          phantom: true,
        });
      }
      if (info.dependencies) walkDeps(info.dependencies);
    }
  }
  walkDeps(dependencies);

  return hits;
}

function checkYarnLock(lockPath) {
  const text = readText(lockPath);
  if (!text) return [];

  const hits = [];
  const lines = text.split("\n");

  let inAxiosBlock = false;
  let inPhantomBlock = false;
  let blockVersion = null;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Detect axios block header: e.g. "axios@^1.14.1:", "axios@1.14.1:"
    if (/^"?axios@/.test(line) && line.trim().endsWith(":")) {
      inAxiosBlock = true;
      inPhantomBlock = false;
      blockVersion = null;
      continue;
    }

    if (new RegExp(`^"?${PHANTOM_PACKAGE}@`).test(line) && line.trim().endsWith(":")) {
      inPhantomBlock = true;
      inAxiosBlock = false;
      hits.push({
        source: `yarn.lock — PHANTOM DEP ${PHANTOM_PACKAGE} found!`,
        version: "see lockfile",
        phantom: true,
      });
      continue;
    }

    // Inside a block, look for the resolved version
    if (inAxiosBlock) {
      const versionMatch = line.match(/^\s+version\s+"?([^"]+)"?/);
      if (versionMatch) {
        blockVersion = versionMatch[1];
        if (isMaliciousVersion(blockVersion)) {
          hits.push({
            source: "yarn.lock",
            version: blockVersion,
          });
        }
        inAxiosBlock = false;
        blockVersion = null;
        continue;
      }
      // Empty line = end of block
      if (line.trim() === "") {
        inAxiosBlock = false;
        blockVersion = null;
      }
    }

    if (inPhantomBlock && line.trim() === "") {
      inPhantomBlock = false;
    }
  }

  return hits;
}

function checkPnpmLock(lockPath) {
  const text = readText(lockPath);
  if (!text) return [];

  const hits = [];
  const lines = text.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // pnpm lockfile v6+ format: /axios@1.14.1 or axios@1.14.1:
    const axiosMatch = line.match(/[/ ]axios@([\d.]+)/);
    if (axiosMatch && isMaliciousVersion(axiosMatch[1])) {
      hits.push({
        source: "pnpm-lock.yaml",
        version: axiosMatch[1],
      });
    }

    // Detect phantom dependency
    if (line.includes(PHANTOM_PACKAGE)) {
      hits.push({
        source: `pnpm-lock.yaml — PHANTOM DEP ${PHANTOM_PACKAGE} found!`,
        version: "see lockfile",
        phantom: true,
      });
    }
  }

  return hits;
}

function checkPackageJson(pkgPath) {
  const pkg = readJSON(pkgPath);
  if (!pkg) return [];

  const hits = [];
  const allDeps = {
    ...pkg.dependencies,
    ...pkg.devDependencies,
    ...pkg.optionalDependencies,
    ...pkg.peerDependencies,
  };

  if (allDeps.axios && isMaliciousVersion(allDeps.axios)) {
    hits.push({
      source: "package.json dependency",
      version: allDeps.axios,
    });
  }

  if (allDeps[PHANTOM_PACKAGE]) {
    hits.push({
      source: `package.json — PHANTOM DEP ${PHANTOM_PACKAGE} found!`,
      version: allDeps[PHANTOM_PACKAGE],
      phantom: true,
    });
  }

  return hits;
}

function checkNodeModules(projectDir) {
  const hits = [];

  // Check installed axios version
  const axiosPkg = path.join(projectDir, "node_modules", "axios", "package.json");
  if (fileExists(axiosPkg)) {
    const pkg = readJSON(axiosPkg);
    if (pkg && isMaliciousVersion(pkg.version)) {
      hits.push({
        source: "node_modules/axios/package.json (INSTALLED)",
        version: pkg.version,
        installed: true,
      });
    }
  }

  // Check for phantom dependency directory
  const phantomDir = path.join(projectDir, "node_modules", PHANTOM_PACKAGE);
  if (fileExists(phantomDir)) {
    const phantomPkg = readJSON(path.join(phantomDir, "package.json"));
    hits.push({
      source: `node_modules/${PHANTOM_PACKAGE} (PHANTOM DEP DIRECTORY EXISTS!)`,
      version: phantomPkg?.version || "unknown — possibly self-deleted",
      phantom: true,
      critical: true,
    });
  }

  return hits;
}

// ─── RAT artifact check ───────────────────────────────────────────────────────

function checkRatArtifacts() {
  const platform = os.platform();
  const artifacts = RAT_ARTIFACTS[platform] || [];
  const found = [];

  for (const artifact of artifacts) {
    if (fileExists(artifact)) {
      found.push(artifact);
    }
  }

  return found;
}

// ─── Directory scanner ────────────────────────────────────────────────────────

const SKIP_DIRS = new Set([
  "node_modules",
  ".git",
  ".svn",
  ".hg",
  "dist",
  "build",
  ".cache",
  ".next",
  ".nuxt",
  "coverage",
  ".yarn",
]);

// Truncate a path for display so it fits in one terminal line
function truncatePath(p, maxLen = 72) {
  if (p.length <= maxLen) return p;
  return "..." + p.slice(p.length - (maxLen - 3));
}

// Overwrite the current terminal line with a live status message
function liveStatus(dirsVisited, projectsFound, currentDir) {
  if (NO_COLOR || !process.stdout.isTTY) return;
  const label =
    `${c.dim}  Explorando: dirs=${dirsVisited}  proyectos=${projectsFound}` +
    `  → ${truncatePath(currentDir)}${c.reset}`;
  process.stdout.write(`\r\x1b[K${label}`);
}

// Walk and scan simultaneously, calling onProject for each project found
function walkAndScan(rootDir, maxDepth, onProject) {
  let dirsVisited = 0;
  let projectsFound = 0;

  function walk(dir, depth) {
    if (depth > maxDepth) return;

    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }

    dirsVisited++;
    liveStatus(dirsVisited, projectsFound, dir);

    const hasPackageJson = entries.some(
      (e) => e.isFile() && e.name === "package.json"
    );

    if (hasPackageJson) {
      projectsFound++;
      // Clear the live status line before printing project result
      if (!NO_COLOR && process.stdout.isTTY) process.stdout.write(`\r\x1b[K`);
      onProject(dir);
    }

    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      if (SKIP_DIRS.has(entry.name)) continue;
      walk(path.join(dir, entry.name), depth + 1);
    }
  }

  walk(rootDir, 0);

  // Clear live status line when done
  if (!NO_COLOR && process.stdout.isTTY) process.stdout.write(`\r\x1b[K`);

  return { dirsVisited, projectsFound };
}

// ─── Scan a single project ────────────────────────────────────────────────────

function scanProject(projectDir) {
  const results = {
    dir: projectDir,
    findings: [],
    phantomFound: false,
    installedMalware: false,
  };

  // 1. package.json
  const pkgJsonPath = path.join(projectDir, "package.json");
  if (fileExists(pkgJsonPath)) {
    const hits = checkPackageJson(pkgJsonPath);
    results.findings.push(...hits);
  }

  // 2. package-lock.json
  const pkgLockPath = path.join(projectDir, "package-lock.json");
  if (fileExists(pkgLockPath)) {
    const hits = checkPackageLock(pkgLockPath);
    results.findings.push(...hits);
  }

  // 3. yarn.lock
  const yarnLockPath = path.join(projectDir, "yarn.lock");
  if (fileExists(yarnLockPath)) {
    const hits = checkYarnLock(yarnLockPath);
    results.findings.push(...hits);
  }

  // 4. pnpm-lock.yaml
  const pnpmLockPath = path.join(projectDir, "pnpm-lock.yaml");
  if (fileExists(pnpmLockPath)) {
    const hits = checkPnpmLock(pnpmLockPath);
    results.findings.push(...hits);
  }

  // 5. node_modules (installed packages)
  const nmPath = path.join(projectDir, "node_modules");
  if (fileExists(nmPath)) {
    const hits = checkNodeModules(projectDir);
    results.findings.push(...hits);
  }

  // Aggregate flags
  for (const f of results.findings) {
    if (f.phantom || f.critical) results.phantomFound = true;
    if (f.installed) results.installedMalware = true;
  }

  return results;
}

// ─── Output formatting ────────────────────────────────────────────────────────

function severityLabel(finding) {
  if (finding.critical) return `${c.bgRed}${c.bold} CRITICAL `;
  if (finding.phantom) return `${c.bgRed}${c.bold} HIGH     `;
  if (finding.installed) return `${c.bgRed}${c.bold} CRITICAL `;
  return `${c.bgYellow}${c.bold} MEDIUM   `;
}

function printProjectResult(result) {
  const relDir = result.dir;

  if (result.findings.length === 0) {
    console.log(`  ${c.green}✓${c.reset} ${c.dim}${relDir}${c.reset}`);
    return;
  }

  const hasInstalled = result.installedMalware;
  const hasPhantom = result.phantomFound;
  const icon = hasInstalled || hasPhantom ? `${c.red}✖` : `${c.yellow}⚠`;

  console.log(`\n  ${icon}${c.reset} ${c.bold}${relDir}${c.reset}`);

  for (const finding of result.findings) {
    const sev = severityLabel(finding);
    console.log(
      `    ${sev}${c.reset} ${c.yellow}${finding.source}${c.reset} — version: ${c.red}${finding.version}${c.reset}`
    );
    if (finding.integrity) {
      console.log(`             integrity: ${c.dim}${finding.integrity}${c.reset}`);
    }
  }
}

function printSummary(allResults, ratArtifacts) {
  const total = allResults.length;
  const vuln = allResults.filter((r) => r.findings.length > 0);
  const critical = allResults.filter((r) => r.installedMalware || r.phantomFound);
  const anythingFound = vuln.length > 0 || ratArtifacts.length > 0;

  printSection("SCAN SUMMARY");

  console.log(`  Proyectos escaneados  : ${c.bold}${total}${c.reset}`);

  if (!anythingFound) {
    console.log(
      `\n  ${c.bgGreen}${c.bold}  ✓ NINGÚN PROYECTO AFECTADO  ${c.reset}\n`
    );
    console.log(
      `  ${c.green}No se encontraron versiones maliciosas de axios (1.14.1 / 0.30.4)${c.reset}`
    );
    console.log(
      `  ${c.green}No se encontró la dependencia fantasma plain-crypto-js${c.reset}`
    );
    console.log(
      `  ${c.green}No se encontraron artefactos del RAT en este sistema${c.reset}\n`
    );
    return;
  }

  // Solo mostrar detalles si hay algo que reportar
  console.log(
    `  Potencialmente afectados : ${c.red}${c.bold}${vuln.length}${c.reset}`
  );
  console.log(
    `  Críticos (evidencia RAT) : ${critical.length > 0 ? c.red : c.green}${c.bold}${critical.length}${c.reset}`
  );

  if (ratArtifacts.length > 0) {
    printSection("ARTEFACTOS DEL RAT ENCONTRADOS EN ESTE SISTEMA");
    console.log(
      `  ${c.bgRed}${c.bold} !!! COMPROMISO DEL SISTEMA DETECTADO !!! ${c.reset}`
    );
    for (const artifact of ratArtifacts) {
      console.log(`  ${c.red}  ► ${artifact}${c.reset}`);
    }
  }

  printSection("IOCs (Indicadores de Compromiso)");
  console.log(`  Dominio C2  : ${c.red}${C2_DOMAIN}${c.reset}`);
  console.log(`  IP C2       : ${c.red}${C2_IP}:8000${c.reset}`);
  console.log(`  Endpoint C2 : /6202033`);

  printSection("HASHES DE PAQUETES MALICIOSOS (SHA1)");
  for (const [pkg, hash] of Object.entries(MALICIOUS_HASHES)) {
    console.log(`  ${c.yellow}${pkg}${c.reset} → ${c.dim}${hash}${c.reset}`);
  }

  printSection("REMEDIACIÓN");
  console.log(`
  1. ${c.bold}Fijar versiones seguras:${c.reset}
     npm install axios@${SAFE_VERSIONS["1.x"]}   (si usas 1.x)
     npm install axios@${SAFE_VERSIONS["0.x"]}  (si usas 0.x)

  2. ${c.bold}Eliminar la dependencia fantasma:${c.reset}
     rm -rf node_modules/plain-crypto-js
     npm ci --ignore-scripts

  3. ${c.bold}Bloquear tráfico C2 en firewall/DNS:${c.reset}
     ${C2_DOMAIN}  →  ${C2_IP}

  4. ${c.bold}Verificar artefactos del RAT:${c.reset}
     Windows : %PROGRAMDATA%\\wt.exe  y  %TEMP%\\6202033.ps1
     macOS   : /Library/Caches/com.apple.act.mond
     Linux   : /tmp/ld.py

  5. ${c.bold}Si se encontraron artefactos del RAT:${c.reset}
     - Asumir COMPROMISO TOTAL DEL SISTEMA
     - Reconstruir la máquina desde un estado limpio
     - Rotar TODAS las credenciales (SSH, npm tokens, AWS/GCP/Azure, .env)
     - Auditar pipelines CI/CD que ejecutaron npm install entre
       00:21 UTC y 03:15 UTC del 31 de marzo de 2026
`);
}

// ─── Main ─────────────────────────────────────────────────────────────────────

function main() {
  const args = process.argv.slice(2);

  if (args.length === 0 || args[0] === "--help" || args[0] === "-h") {
    printBanner();
    console.log(`${c.bold}USAGE:${c.reset}
  node axios-vuln-scanner.js <path> [options]

${c.bold}OPTIONS:${c.reset}
  --depth <n>    Maximum directory depth to scan (default: ∞ infinite)
  --no-color     Disable colored output
  --help, -h     Show this help

${c.bold}EXAMPLES:${c.reset}
  node axios-vuln-scanner.js .
  node axios-vuln-scanner.js /home/user/projects
  node axios-vuln-scanner.js C:\\\\Users\\\\me\\\\source --depth 5
`);
    process.exit(0);
  }

  const targetPath = path.resolve(args[0]);
  let maxDepth = Infinity;

  const depthIdx = args.indexOf("--depth");
  if (depthIdx !== -1 && args[depthIdx + 1]) {
    maxDepth = parseInt(args[depthIdx + 1], 10) || Infinity;
  }

  if (!fileExists(targetPath)) {
    console.error(`${c.red}Error: Path does not exist: ${targetPath}${c.reset}`);
    process.exit(1);
  }

  printBanner();

  const depthLabel = maxDepth === Infinity ? "∞" : maxDepth;
  console.log(
    `${c.bold}Scanning:${c.reset} ${c.cyan}${targetPath}${c.reset} (max depth: ${depthLabel})\n`
  );

  printSection("SCANNING IN PROGRESS");

  const allResults = [];

  const { dirsVisited, projectsFound } = walkAndScan(
    targetPath,
    maxDepth,
    (projectDir) => {
      const result = scanProject(projectDir);
      allResults.push(result);
      printProjectResult(result);
    }
  );

  console.log(
    `\n  ${c.dim}Directorios explorados: ${dirsVisited}  |  Proyectos encontrados: ${projectsFound}${c.reset}`
  );

  // Check RAT artifacts on THIS machine
  const ratArtifacts = checkRatArtifacts();

  printSummary(allResults, ratArtifacts);

  // Exit with non-zero if vulnerabilities found
  const hasVuln = allResults.some((r) => r.findings.length > 0) || ratArtifacts.length > 0;
  process.exit(hasVuln ? 1 : 0);
}

main();
