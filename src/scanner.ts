import * as fs from 'fs';
import * as path from 'path';
import {
  MasterPackages,
  PackageJson,
  PackageLock,
  ScanResult,
  ScanSummary,
  SarifResult,
} from './types';
import masterPackagesData from '../master-packages.json';

const masterPackages: MasterPackages = masterPackagesData as MasterPackages;

// Create a Set for O(1) lookup
const affectedPackageNames = new Set(
  masterPackages.packages.map((p) => p.name)
);

export function isAffected(packageName: string): boolean {
  return affectedPackageNames.has(packageName);
}

export function getPackageSeverity(
  packageName: string
): 'critical' | 'high' | 'medium' | 'low' {
  const pkg = masterPackages.packages.find((p) => p.name === packageName);
  return pkg?.severity || 'critical';
}

export function parsePackageJson(filePath: string): PackageJson | null {
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    return JSON.parse(content) as PackageJson;
  } catch {
    return null;
  }
}

export function parsePackageLock(filePath: string): PackageLock | null {
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    return JSON.parse(content) as PackageLock;
  } catch {
    return null;
  }
}

export function parseYarnLock(filePath: string): Map<string, string> | null {
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    const packages = new Map<string, string>();

    // Simple yarn.lock parser - extract package names
    const lines = content.split('\n');
    let currentPackage = '';

    for (const line of lines) {
      // Package declaration lines start without whitespace and contain @
      if (!line.startsWith(' ') && !line.startsWith('#') && line.includes('@')) {
        // Parse package name from lines like:
        // "@asyncapi/diff@^1.0.0":
        // "posthog-node@^5.0.0":
        const match = line.match(/^"?(@?[^@\s"]+)/);
        if (match) {
          currentPackage = match[1];
        }
      }
      // Version line
      if (line.trim().startsWith('version') && currentPackage) {
        const versionMatch = line.match(/version\s+"([^"]+)"/);
        if (versionMatch) {
          packages.set(currentPackage, versionMatch[1]);
        }
      }
    }

    return packages;
  } catch {
    return null;
  }
}

export function scanPackageJson(
  filePath: string,
  isDirect: boolean = true
): ScanResult[] {
  const results: ScanResult[] = [];
  const pkg = parsePackageJson(filePath);

  if (!pkg) return results;

  const allDeps = {
    ...pkg.dependencies,
    ...pkg.devDependencies,
    ...pkg.peerDependencies,
    ...pkg.optionalDependencies,
  };

  for (const [name, version] of Object.entries(allDeps)) {
    if (isAffected(name)) {
      results.push({
        package: name,
        version: version || 'unknown',
        severity: getPackageSeverity(name),
        isDirect,
        location: filePath,
      });
    }
  }

  return results;
}

export function scanPackageLock(filePath: string): ScanResult[] {
  const results: ScanResult[] = [];
  const lock = parsePackageLock(filePath);

  if (!lock) return results;

  // Scan v2/v3 lockfile format (packages object)
  if (lock.packages) {
    for (const [pkgPath, entry] of Object.entries(lock.packages)) {
      // Extract package name from path like "node_modules/@asyncapi/diff"
      const match = pkgPath.match(/node_modules\/(.+)$/);
      if (match) {
        const name = match[1];
        if (isAffected(name)) {
          results.push({
            package: name,
            version: entry.version || 'unknown',
            severity: getPackageSeverity(name),
            isDirect: !pkgPath.includes('node_modules/node_modules'),
            location: filePath,
          });
        }
      }
    }
  }

  // Scan v1 lockfile format (dependencies object)
  if (lock.dependencies) {
    const scanDependencies = (
      deps: Record<string, any>,
      isDirect: boolean
    ) => {
      for (const [name, entry] of Object.entries(deps)) {
        if (isAffected(name)) {
          results.push({
            package: name,
            version: entry.version || 'unknown',
            severity: getPackageSeverity(name),
            isDirect,
            location: filePath,
          });
        }
        // Recursively scan nested dependencies
        if (entry.dependencies) {
          scanDependencies(entry.dependencies, false);
        }
      }
    };
    scanDependencies(lock.dependencies, true);
  }

  return results;
}

export function scanYarnLock(filePath: string): ScanResult[] {
  const results: ScanResult[] = [];
  const packages = parseYarnLock(filePath);

  if (!packages) return results;

  for (const [name, version] of packages.entries()) {
    if (isAffected(name)) {
      results.push({
        package: name,
        version,
        severity: getPackageSeverity(name),
        isDirect: false, // yarn.lock doesn't indicate direct vs transitive
        location: filePath,
      });
    }
  }

  return results;
}

export function findLockfiles(directory: string): string[] {
  const lockfiles: string[] = [];
  const possibleFiles = [
    'package-lock.json',
    'yarn.lock',
    'pnpm-lock.yaml',
    'npm-shrinkwrap.json',
  ];

  // Search in root and subdirectories (for monorepos)
  const searchDir = (dir: string, depth: number = 0) => {
    if (depth > 5) return; // Limit depth to prevent excessive recursion

    try {
      const entries = fs.readdirSync(dir, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);

        if (entry.isFile() && possibleFiles.includes(entry.name)) {
          lockfiles.push(fullPath);
        } else if (
          entry.isDirectory() &&
          !entry.name.startsWith('.') &&
          entry.name !== 'node_modules'
        ) {
          searchDir(fullPath, depth + 1);
        }
      }
    } catch {
      // Skip directories we can't read
    }
  };

  searchDir(directory);
  return lockfiles;
}

export function findPackageJsonFiles(directory: string): string[] {
  const packageFiles: string[] = [];

  const searchDir = (dir: string, depth: number = 0) => {
    if (depth > 5) return;

    try {
      const entries = fs.readdirSync(dir, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);

        if (entry.isFile() && entry.name === 'package.json') {
          packageFiles.push(fullPath);
        } else if (
          entry.isDirectory() &&
          !entry.name.startsWith('.') &&
          entry.name !== 'node_modules'
        ) {
          searchDir(fullPath, depth + 1);
        }
      }
    } catch {
      // Skip directories we can't read
    }
  };

  searchDir(directory);
  return packageFiles;
}

export function runScan(
  directory: string,
  scanLockfiles: boolean = true
): ScanSummary {
  const startTime = Date.now();
  const allResults: ScanResult[] = [];
  const scannedFiles: string[] = [];
  const seenPackages = new Set<string>();

  // Scan package.json files
  const packageJsonFiles = findPackageJsonFiles(directory);
  for (const file of packageJsonFiles) {
    scannedFiles.push(file);
    const results = scanPackageJson(file, true);
    for (const result of results) {
      const key = `${result.package}@${result.version}`;
      if (!seenPackages.has(key)) {
        seenPackages.add(key);
        allResults.push(result);
      }
    }
  }

  // Scan lockfiles if enabled
  if (scanLockfiles) {
    const lockfiles = findLockfiles(directory);
    for (const file of lockfiles) {
      scannedFiles.push(file);

      let results: ScanResult[] = [];
      if (file.endsWith('package-lock.json') || file.endsWith('npm-shrinkwrap.json')) {
        results = scanPackageLock(file);
      } else if (file.endsWith('yarn.lock')) {
        results = scanYarnLock(file);
      }
      // TODO: Add pnpm-lock.yaml support

      for (const result of results) {
        const key = `${result.package}@${result.version}`;
        if (!seenPackages.has(key)) {
          seenPackages.add(key);
          allResults.push(result);
        }
      }
    }
  }

  // Sort results by severity
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  allResults.sort(
    (a, b) => severityOrder[a.severity] - severityOrder[b.severity]
  );

  return {
    totalDependencies: seenPackages.size,
    affectedCount: allResults.length,
    cleanCount: seenPackages.size - allResults.length,
    results: allResults,
    scannedFiles,
    scanTime: Date.now() - startTime,
  };
}

export function generateSarifReport(summary: ScanSummary): SarifResult {
  const rules: any[] = [];
  const results: any[] = [];

  // Create unique rules for each affected package
  const ruleMap = new Map<string, string>();
  let ruleIndex = 0;

  for (const result of summary.results) {
    let ruleId = ruleMap.get(result.package);
    if (!ruleId) {
      ruleId = `SHAI-HULUD-${String(++ruleIndex).padStart(4, '0')}`;
      ruleMap.set(result.package, ruleId);

      rules.push({
        id: ruleId,
        name: `CompromisedPackage_${result.package.replace(/[^a-zA-Z0-9]/g, '_')}`,
        shortDescription: {
          text: `Compromised package: ${result.package}`,
        },
        fullDescription: {
          text: `The package "${result.package}" has been identified as compromised in the Shai-Hulud 2.0 supply chain attack. This package may contain malicious code that steals credentials and exfiltrates sensitive data.`,
        },
        helpUri:
          'https://www.aikido.dev/blog/shai-hulud-strikes-again-hitting-zapier-ensdomains',
        defaultConfiguration: {
          level: result.severity === 'critical' ? 'error' : 'warning',
        },
      });
    }

    results.push({
      ruleId,
      level: result.severity === 'critical' ? 'error' : 'warning',
      message: {
        text: `Compromised package "${result.package}@${result.version}" detected. This package is part of the Shai-Hulud 2.0 supply chain attack.`,
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: result.location,
            },
          },
        },
      ],
    });
  }

  return {
    $schema:
      'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'shai-hulud-detector',
            version: '1.0.0',
            informationUri:
              'https://github.com/gensecaihq/Shai-Hulud-2.0-Detector',
            rules,
          },
        },
        results,
      },
    ],
  };
}

export function formatTextReport(summary: ScanSummary): string {
  const lines: string[] = [];

  lines.push('');
  lines.push('='.repeat(60));
  lines.push('  SHAI-HULUD 2.0 SUPPLY CHAIN ATTACK DETECTOR');
  lines.push('='.repeat(60));
  lines.push('');

  if (summary.affectedCount === 0) {
    lines.push('  STATUS: CLEAN');
    lines.push('  No compromised packages detected.');
  } else {
    lines.push(`  STATUS: AFFECTED (${summary.affectedCount} package(s) found)`);
    lines.push('');
    lines.push('  AFFECTED PACKAGES:');
    lines.push('-'.repeat(60));

    for (const result of summary.results) {
      const badge =
        result.severity === 'critical' ? '[CRITICAL]' : `[${result.severity.toUpperCase()}]`;
      const direct = result.isDirect ? '(direct)' : '(transitive)';
      lines.push(`  ${badge} ${result.package}@${result.version} ${direct}`);
      lines.push(`         Location: ${result.location}`);
    }
  }

  lines.push('');
  lines.push('-'.repeat(60));
  lines.push(`  Files scanned: ${summary.scannedFiles.length}`);
  lines.push(`  Scan time: ${summary.scanTime}ms`);
  lines.push(`  Database version: ${masterPackages.version}`);
  lines.push(`  Last updated: ${masterPackages.lastUpdated}`);
  lines.push('='.repeat(60));
  lines.push('');

  if (summary.affectedCount > 0) {
    lines.push('  IMMEDIATE ACTIONS REQUIRED:');
    lines.push('  1. Do NOT run npm install until packages are updated');
    lines.push('  2. Rotate all credentials (npm, GitHub, AWS, etc.)');
    lines.push('  3. Check for unauthorized GitHub self-hosted runners named "SHA1HULUD"');
    lines.push('  4. Audit GitHub repos for "Shai-Hulud: The Second Coming" description');
    lines.push('');
    lines.push('  For more information:');
    lines.push('  https://www.aikido.dev/blog/shai-hulud-strikes-again-hitting-zapier-ensdomains');
    lines.push('');
  }

  return lines.join('\n');
}

export function getMasterPackagesInfo() {
  return {
    version: masterPackages.version,
    lastUpdated: masterPackages.lastUpdated,
    totalPackages: masterPackages.packages.length,
    attackInfo: masterPackages.attackInfo,
    indicators: masterPackages.indicators,
  };
}
