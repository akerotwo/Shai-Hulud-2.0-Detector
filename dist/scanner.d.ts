import { PackageJson, PackageLock, ScanResult, ScanSummary, SarifResult } from './types';
export declare function isAffected(packageName: string): boolean;
export declare function getPackageSeverity(packageName: string): 'critical' | 'high' | 'medium' | 'low';
export declare function parsePackageJson(filePath: string): PackageJson | null;
export declare function parsePackageLock(filePath: string): PackageLock | null;
export declare function parseYarnLock(filePath: string): Map<string, string> | null;
export declare function scanPackageJson(filePath: string, isDirect?: boolean): ScanResult[];
export declare function scanPackageLock(filePath: string): ScanResult[];
export declare function scanYarnLock(filePath: string): ScanResult[];
export declare function findLockfiles(directory: string): string[];
export declare function findPackageJsonFiles(directory: string): string[];
export declare function runScan(directory: string, scanLockfiles?: boolean): ScanSummary;
export declare function generateSarifReport(summary: ScanSummary): SarifResult;
export declare function formatTextReport(summary: ScanSummary): string;
export declare function getMasterPackagesInfo(): {
    version: string;
    lastUpdated: string;
    totalPackages: number;
    attackInfo: {
        name: string;
        alias: string;
        firstDetected: string;
        description: string;
    };
    indicators: {
        maliciousFiles: string[];
        maliciousWorkflows: string[];
        fileHashes: Record<string, string>;
        gitHubIndicators: {
            runnerName: string;
            repoDescription: string;
        };
    };
};
