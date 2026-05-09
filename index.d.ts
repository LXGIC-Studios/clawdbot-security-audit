/**
 * AI Security Audit - AI-powered security scanner
 * Detect vulnerabilities with GPT analysis and comprehensive security checks
 */

export interface SecurityConfig {
  paths: string[];
  level: 'low' | 'medium' | 'high' | 'critical';
  aiModel?: 'gpt-4' | 'gpt-3.5' | 'claude-3' | 'claude-2';
  excludePatterns?: string[];
}

export interface Vulnerability {
  id: string;
  type: 'code' | 'dependency' | 'config' | 'secret';
  severity: 'low' | 'medium' | 'high' | 'critical';
  file: string;
  line?: number;
  description: string;
  suggestion: string;
  snippet?: string;
  confidence: number;
}

export interface SecurityReport {
  timestamp: number;
  scannedFiles: number;
  vulnerabilities: Vulnerability[];
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  aiAnalysis: string;
}

export interface SecretMatch {
  match: string;
  file: string;
  line: number;
  type: 'api_key' | 'password' | 'token' | 'private_key' | 'unknown';
  severity: 'high' | 'medium' | 'low';
}

export interface DependencyIssue {
  package: string;
  current: string;
  latest: string;
  vulnerability?: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
}

export declare function auditSecurity(config: SecurityConfig): Promise<SecurityReport>;

export declare function scanForSecrets(paths: string[]): Promise<SecretMatch[]>;
export declare function scanDependencies(): Promise<DependencyIssue[]>;

export declare function generateReport(report: SecurityReport): Promise<string>;
export declare function exportReport(report: SecurityReport, format: 'json' | 'html' | 'markdown'): Promise<string>;

export declare function autoFix(report: SecurityReport): Promise<{
  fixed: number;
  issues: string[];
}>;

export declare const SecurityRules: {
  secrets: RegExp[];
  patterns: Array<{
    name: string;
    pattern: RegExp;
    severity: 'low' | 'medium' | 'high' | 'critical';
  }>;
};

export { auditSecurity as default };