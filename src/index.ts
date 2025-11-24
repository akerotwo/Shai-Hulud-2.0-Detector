import * as core from '@actions/core';
import * as github from '@actions/github';
import * as fs from 'fs';
import * as path from 'path';
import {
  runScan,
  formatTextReport,
  generateSarifReport,
  getMasterPackagesInfo,
} from './scanner';
import { ActionInputs } from './types';

function getInputs(): ActionInputs {
  return {
    failOnCritical: core.getBooleanInput('fail-on-critical'),
    failOnHigh: core.getBooleanInput('fail-on-high'),
    failOnAny: core.getBooleanInput('fail-on-any'),
    scanLockfiles: core.getBooleanInput('scan-lockfiles'),
    scanNodeModules: core.getBooleanInput('scan-node-modules'),
    outputFormat: core.getInput('output-format') as 'text' | 'json' | 'sarif',
    workingDirectory: core.getInput('working-directory') || process.cwd(),
  };
}

async function run(): Promise<void> {
  try {
    const inputs = getInputs();

    core.info('');
    core.info('Shai-Hulud 2.0 Detector');
    core.info('=======================');

    // Display database info
    const dbInfo = getMasterPackagesInfo();
    core.info(`Database version: ${dbInfo.version}`);
    core.info(`Last updated: ${dbInfo.lastUpdated}`);
    core.info(`Total known affected packages: ${dbInfo.totalPackages}`);
    core.info('');

    // Resolve working directory
    const workDir = path.resolve(inputs.workingDirectory);
    core.info(`Scanning directory: ${workDir}`);

    if (!fs.existsSync(workDir)) {
      core.setFailed(`Working directory does not exist: ${workDir}`);
      return;
    }

    // Run the scan
    core.info('Starting scan...');
    const summary = runScan(workDir, inputs.scanLockfiles);

    // Output results based on format
    switch (inputs.outputFormat) {
      case 'json':
        core.info('');
        core.info('JSON Report:');
        core.info(JSON.stringify(summary, null, 2));
        break;

      case 'sarif':
        const sarifReport = generateSarifReport(summary);
        const sarifPath = path.join(workDir, 'shai-hulud-results.sarif');
        fs.writeFileSync(sarifPath, JSON.stringify(sarifReport, null, 2));
        core.info(`SARIF report written to: ${sarifPath}`);
        core.setOutput('sarif-file', sarifPath);
        break;

      case 'text':
      default:
        core.info(formatTextReport(summary));
        break;
    }

    // Set outputs
    core.setOutput('affected-count', summary.affectedCount.toString());
    core.setOutput('scan-time', summary.scanTime.toString());
    core.setOutput('status', summary.affectedCount > 0 ? 'affected' : 'clean');
    core.setOutput('results', JSON.stringify(summary.results));

    // Create annotations for affected packages
    if (summary.affectedCount > 0) {
      for (const result of summary.results) {
        const annotation = {
          title: `Compromised Package: ${result.package}`,
          file: result.location,
          startLine: 1,
        };

        if (result.severity === 'critical') {
          core.error(
            `[CRITICAL] ${result.package}@${result.version} - Shai-Hulud 2.0 compromised package detected`,
            annotation
          );
        } else {
          core.warning(
            `[${result.severity.toUpperCase()}] ${result.package}@${result.version} - Shai-Hulud 2.0 compromised package detected`,
            annotation
          );
        }
      }

      // Create job summary
      await createJobSummary(summary);
    }

    // Determine if we should fail
    let shouldFail = false;
    let failReason = '';

    if (inputs.failOnAny && summary.affectedCount > 0) {
      shouldFail = true;
      failReason = `${summary.affectedCount} compromised package(s) detected`;
    } else if (inputs.failOnCritical) {
      const criticalCount = summary.results.filter(
        (r) => r.severity === 'critical'
      ).length;
      if (criticalCount > 0) {
        shouldFail = true;
        failReason = `${criticalCount} critical severity package(s) detected`;
      }
    } else if (inputs.failOnHigh) {
      const highOrAbove = summary.results.filter(
        (r) => r.severity === 'critical' || r.severity === 'high'
      ).length;
      if (highOrAbove > 0) {
        shouldFail = true;
        failReason = `${highOrAbove} high/critical severity package(s) detected`;
      }
    }

    if (shouldFail) {
      core.setFailed(
        `Shai-Hulud 2.0 supply chain attack detected: ${failReason}`
      );
    } else if (summary.affectedCount > 0) {
      core.warning(
        `Shai-Hulud 2.0: ${summary.affectedCount} affected package(s) found (not failing due to configuration)`
      );
    } else {
      core.info('Scan complete. No compromised packages detected.');
    }
  } catch (error) {
    if (error instanceof Error) {
      core.setFailed(`Action failed: ${error.message}`);
    } else {
      core.setFailed('Action failed with unknown error');
    }
  }
}

async function createJobSummary(summary: any): Promise<void> {
  const lines: string[] = [];

  lines.push('# Shai-Hulud 2.0 Supply Chain Attack Scan Results');
  lines.push('');
  lines.push(
    `> **Status:** ${summary.affectedCount > 0 ? 'AFFECTED' : 'CLEAN'}`
  );
  lines.push('');

  if (summary.affectedCount > 0) {
    lines.push('## Affected Packages');
    lines.push('');
    lines.push('| Package | Version | Severity | Type |');
    lines.push('|---------|---------|----------|------|');

    for (const result of summary.results) {
      const type = result.isDirect ? 'Direct' : 'Transitive';
      lines.push(
        `| \`${result.package}\` | ${result.version} | ${result.severity.toUpperCase()} | ${type} |`
      );
    }

    lines.push('');
    lines.push('## Immediate Actions Required');
    lines.push('');
    lines.push('1. **Do NOT run `npm install`** until packages are updated');
    lines.push('2. **Rotate all credentials** (npm, GitHub, AWS, GCP, Azure)');
    lines.push(
      '3. **Check for unauthorized self-hosted runners** named "SHA1HULUD"'
    );
    lines.push(
      '4. **Audit GitHub repos** for "Shai-Hulud: The Second Coming" description'
    );
    lines.push('');
    lines.push('## More Information');
    lines.push('');
    lines.push(
      '- [Aikido Security Analysis](https://www.aikido.dev/blog/shai-hulud-strikes-again-hitting-zapier-ensdomains)'
    );
    lines.push(
      '- [Wiz.io Investigation](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack)'
    );
  } else {
    lines.push(
      'No compromised packages were detected in your dependencies.'
    );
  }

  lines.push('');
  lines.push('---');
  lines.push(`*Scanned ${summary.scannedFiles.length} files in ${summary.scanTime}ms*`);

  await core.summary.addRaw(lines.join('\n')).write();
}

run();
