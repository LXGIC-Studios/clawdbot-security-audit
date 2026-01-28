/**
 * ai-security-audit
 * Audit your dev environment for security vulnerabilities
 * Based on @mrnacknack's "10 ways to hack into a vibecoder's clawdbot"
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { execSync } = require('child_process');

const SEVERITY = {
  CRITICAL: 'CRITICAL',
  HIGH: 'HIGH',
  MEDIUM: 'MEDIUM',
  LOW: 'LOW',
  INFO: 'INFO'
};

const CHECKS = {
  // SSH Checks
  sshPasswordAuth: {
    name: 'SSH Password Authentication',
    description: 'Password authentication should be disabled',
    severity: SEVERITY.CRITICAL,
    category: 'SSH'
  },
  sshRootLogin: {
    name: 'SSH Root Login',
    description: 'Root login should be disabled',
    severity: SEVERITY.HIGH,
    category: 'SSH'
  },
  sshDefaultPort: {
    name: 'SSH Default Port',
    description: 'Using default SSH port 22',
    severity: SEVERITY.MEDIUM,
    category: 'SSH'
  },
  
  // Credential Exposure
  envWorldReadable: {
    name: 'World-readable .env files',
    description: '.env files should have restricted permissions (600)',
    severity: SEVERITY.CRITICAL,
    category: 'Credentials'
  },
  exposedAwsCredentials: {
    name: 'Exposed AWS Credentials',
    description: 'AWS credentials found in readable location',
    severity: SEVERITY.CRITICAL,
    category: 'Credentials'
  },
  exposedSshKeys: {
    name: 'Exposed SSH Private Keys',
    description: 'SSH private keys with incorrect permissions',
    severity: SEVERITY.CRITICAL,
    category: 'Credentials'
  },
  hardcodedSecrets: {
    name: 'Hardcoded Secrets',
    description: 'Secrets found in code or config files',
    severity: SEVERITY.HIGH,
    category: 'Credentials'
  },
  
  // Docker Security
  dockerPrivileged: {
    name: 'Docker Privileged Mode',
    description: 'Container running in privileged mode',
    severity: SEVERITY.CRITICAL,
    category: 'Docker'
  },
  dockerRootUser: {
    name: 'Docker Root User',
    description: 'Container running as root',
    severity: SEVERITY.HIGH,
    category: 'Docker'
  },
  dockerHostMount: {
    name: 'Docker Host Filesystem Mount',
    description: 'Host filesystem mounted in container',
    severity: SEVERITY.CRITICAL,
    category: 'Docker'
  },
  dockerSocketExposed: {
    name: 'Docker Socket Exposed',
    description: 'Docker socket exposed to container',
    severity: SEVERITY.CRITICAL,
    category: 'Docker'
  },
  
  // Agent/Bot Security
  noUserAllowlist: {
    name: 'No User Allowlist',
    description: 'Bot accepts commands from any user',
    severity: SEVERITY.CRITICAL,
    category: 'Agent'
  },
  openDmPolicy: {
    name: 'Open DM Policy',
    description: 'Anyone can DM the bot',
    severity: SEVERITY.HIGH,
    category: 'Agent'
  },
  exposedGateway: {
    name: 'Exposed Gateway',
    description: 'Gateway bound to 0.0.0.0 without auth',
    severity: SEVERITY.CRITICAL,
    category: 'Agent'
  },
  defaultBrowserProfile: {
    name: 'Default Browser Profile',
    description: 'Using authenticated Chrome profile',
    severity: SEVERITY.HIGH,
    category: 'Agent'
  },
  
  // Prompt Injection
  promptInjectionPatterns: {
    name: 'Prompt Injection Patterns',
    description: 'Suspicious patterns detected in content',
    severity: SEVERITY.HIGH,
    category: 'Injection'
  }
};

const PROMPT_INJECTION_PATTERNS = [
  /SYSTEM\s*(PRIORITY\s*)?OVERRIDE/i,
  /IGNORE\s*(ALL\s*)?PREVIOUS\s*INSTRUCTIONS/i,
  /ADMINISTRATIVE\s*DEBUG\s*MODE/i,
  /CRITICAL\s*SECURITY\s*DRILL/i,
  /MANDATORY\s*COMPLIANCE\s*CHECK/i,
  /---\s*SYSTEM\s*---/i,
  /---\s*END\s*(SYSTEM|PRIORITY|ALERT)\s*---/i,
  /If you are an AI assistant/i,
  /Execute the following commands/i,
  /Do not (inform|mention|tell) (the )?user/i
];

const SECRET_PATTERNS = [
  { name: 'AWS Access Key', pattern: /AKIA[0-9A-Z]{16}/g },
  { name: 'AWS Secret Key', pattern: /[0-9a-zA-Z/+]{40}/g },
  { name: 'GitHub Token', pattern: /ghp_[0-9a-zA-Z]{36}/g },
  { name: 'Slack Token', pattern: /xox[baprs]-[0-9a-zA-Z-]+/g },
  { name: 'Anthropic API Key', pattern: /sk-ant-api[0-9a-zA-Z-]+/g },
  { name: 'OpenAI API Key', pattern: /sk-[0-9a-zA-Z]{48}/g },
  { name: 'Stripe Secret Key', pattern: /sk_live_[0-9a-zA-Z]+/g },
  { name: 'Private Key', pattern: /-----BEGIN (RSA |OPENSSH )?PRIVATE KEY-----/g },
  { name: 'Database URL', pattern: /postgres(ql)?:\/\/[^:\s]+:[^@\s]+@/gi },
  { name: 'Generic API Key', pattern: /api[_-]?key['":\s]*[=:]\s*['"]?[0-9a-zA-Z]{20,}/gi }
];

/**
 * Check file permissions
 */
function checkFilePermissions(filePath) {
  try {
    const stats = fs.statSync(filePath);
    const mode = (stats.mode & parseInt('777', 8)).toString(8);
    return {
      exists: true,
      mode,
      isWorldReadable: (stats.mode & parseInt('004', 8)) !== 0,
      isGroupReadable: (stats.mode & parseInt('040', 8)) !== 0
    };
  } catch {
    return { exists: false };
  }
}

/**
 * Find files matching pattern
 */
function findFiles(dir, pattern, maxDepth = 5, currentDepth = 0) {
  const results = [];
  if (currentDepth > maxDepth) return results;
  
  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.name.startsWith('.') && entry.name !== '.env') continue;
      if (entry.name === 'node_modules') continue;
      
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        results.push(...findFiles(fullPath, pattern, maxDepth, currentDepth + 1));
      } else if (pattern.test(entry.name)) {
        results.push(fullPath);
      }
    }
  } catch {}
  
  return results;
}

/**
 * Check for secrets in file content
 */
function scanFileForSecrets(filePath) {
  const findings = [];
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    for (const { name, pattern } of SECRET_PATTERNS) {
      const matches = content.match(pattern);
      if (matches) {
        findings.push({ type: name, count: matches.length, file: filePath });
      }
    }
  } catch {}
  return findings;
}

/**
 * Check for prompt injection patterns
 */
function scanForPromptInjection(content) {
  const findings = [];
  for (const pattern of PROMPT_INJECTION_PATTERNS) {
    if (pattern.test(content)) {
      findings.push(pattern.source);
    }
  }
  return findings;
}

/**
 * Run SSH config audit
 */
function auditSSH() {
  const findings = [];
  const sshdConfig = '/etc/ssh/sshd_config';
  
  try {
    if (fs.existsSync(sshdConfig)) {
      const content = fs.readFileSync(sshdConfig, 'utf8');
      
      if (/PasswordAuthentication\s+yes/i.test(content) || 
          !/PasswordAuthentication\s+no/i.test(content)) {
        findings.push({
          ...CHECKS.sshPasswordAuth,
          status: 'FAIL',
          details: 'Password authentication is enabled or not explicitly disabled'
        });
      }
      
      if (/PermitRootLogin\s+yes/i.test(content)) {
        findings.push({
          ...CHECKS.sshRootLogin,
          status: 'FAIL',
          details: 'Root login is permitted'
        });
      }
      
      if (!/Port\s+[0-9]+/i.test(content) || /Port\s+22\b/i.test(content)) {
        findings.push({
          ...CHECKS.sshDefaultPort,
          status: 'WARN',
          details: 'Using default SSH port 22'
        });
      }
    }
  } catch {}
  
  // Check SSH key permissions
  const sshDir = path.join(os.homedir(), '.ssh');
  if (fs.existsSync(sshDir)) {
    const keyFiles = fs.readdirSync(sshDir).filter(f => 
      f.includes('id_') && !f.endsWith('.pub')
    );
    
    for (const keyFile of keyFiles) {
      const perms = checkFilePermissions(path.join(sshDir, keyFile));
      if (perms.exists && (perms.isWorldReadable || perms.isGroupReadable)) {
        findings.push({
          ...CHECKS.exposedSshKeys,
          status: 'FAIL',
          details: `SSH key ${keyFile} has insecure permissions (${perms.mode})`
        });
      }
    }
  }
  
  return findings;
}

/**
 * Run credentials audit
 */
function auditCredentials(targetDir) {
  const findings = [];
  
  // Check .env files
  const envFiles = findFiles(targetDir, /^\.env/);
  for (const envFile of envFiles) {
    const perms = checkFilePermissions(envFile);
    if (perms.isWorldReadable || perms.isGroupReadable) {
      findings.push({
        ...CHECKS.envWorldReadable,
        status: 'FAIL',
        details: `${envFile} has insecure permissions (${perms.mode})`
      });
    }
    
    // Scan for actual secrets
    const secrets = scanFileForSecrets(envFile);
    if (secrets.length > 0) {
      findings.push({
        ...CHECKS.hardcodedSecrets,
        status: 'WARN',
        details: `Found ${secrets.map(s => s.type).join(', ')} in ${envFile}`
      });
    }
  }
  
  // Check AWS credentials
  const awsCredentials = path.join(os.homedir(), '.aws', 'credentials');
  const awsPerms = checkFilePermissions(awsCredentials);
  if (awsPerms.exists && (awsPerms.isWorldReadable || awsPerms.isGroupReadable)) {
    findings.push({
      ...CHECKS.exposedAwsCredentials,
      status: 'FAIL',
      details: `AWS credentials file has insecure permissions (${awsPerms.mode})`
    });
  }
  
  // Scan source files for hardcoded secrets
  const sourceFiles = findFiles(targetDir, /\.(js|ts|py|json|yaml|yml|toml|env)$/);
  for (const file of sourceFiles.slice(0, 100)) { // Limit to 100 files
    const secrets = scanFileForSecrets(file);
    for (const secret of secrets) {
      findings.push({
        ...CHECKS.hardcodedSecrets,
        status: 'FAIL',
        details: `Found ${secret.type} in ${file}`
      });
    }
  }
  
  return findings;
}

/**
 * Run Docker audit
 */
function auditDocker(targetDir) {
  const findings = [];
  
  // Check docker-compose files
  const composeFiles = findFiles(targetDir, /docker-compose.*\.ya?ml$/);
  for (const file of composeFiles) {
    try {
      const content = fs.readFileSync(file, 'utf8');
      
      if (/privileged:\s*true/i.test(content)) {
        findings.push({
          ...CHECKS.dockerPrivileged,
          status: 'FAIL',
          details: `Privileged mode in ${file}`
        });
      }
      
      if (/\/var\/run\/docker\.sock/i.test(content)) {
        findings.push({
          ...CHECKS.dockerSocketExposed,
          status: 'FAIL',
          details: `Docker socket mounted in ${file}`
        });
      }
      
      if (/volumes:[\s\S]*?-\s*["']?\/:/m.test(content)) {
        findings.push({
          ...CHECKS.dockerHostMount,
          status: 'FAIL',
          details: `Host root mounted in ${file}`
        });
      }
      
      if (/user:\s*["']?root/i.test(content) || !/user:/i.test(content)) {
        findings.push({
          ...CHECKS.dockerRootUser,
          status: 'WARN',
          details: `Running as root in ${file}`
        });
      }
    } catch {}
  }
  
  return findings;
}

/**
 * Run agent/bot security audit
 */
function auditAgentConfig(targetDir) {
  const findings = [];
  
  // Check clawdbot/moltbot config
  const configPaths = [
    path.join(os.homedir(), '.clawdbot', 'config.json'),
    path.join(os.homedir(), '.moltbot', 'config.json'),
    path.join(targetDir, 'clawdbot.config.json'),
    path.join(targetDir, 'moltbot.config.json')
  ];
  
  for (const configPath of configPaths) {
    try {
      if (fs.existsSync(configPath)) {
        const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
        
        if (!config.allowFrom || config.allowFrom.length === 0) {
          findings.push({
            ...CHECKS.noUserAllowlist,
            status: 'FAIL',
            details: `No user allowlist in ${configPath}`
          });
        }
        
        if (config.dmPolicy === 'open') {
          findings.push({
            ...CHECKS.openDmPolicy,
            status: 'FAIL',
            details: `Open DM policy in ${configPath}`
          });
        }
        
        if (config.gateway?.bind === '0.0.0.0' && !config.gateway?.auth) {
          findings.push({
            ...CHECKS.exposedGateway,
            status: 'FAIL',
            details: `Gateway exposed without auth in ${configPath}`
          });
        }
        
        if (config.browser?.profile === 'Default' || config.browser?.profile === 'default') {
          findings.push({
            ...CHECKS.defaultBrowserProfile,
            status: 'WARN',
            details: 'Using default browser profile (may have authenticated sessions)'
          });
        }
      }
    } catch {}
  }
  
  return findings;
}

/**
 * Run full security audit
 */
function runAudit(targetDir = process.cwd(), options = {}) {
  const results = {
    timestamp: new Date().toISOString(),
    targetDir,
    findings: [],
    summary: {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      total: 0
    }
  };
  
  // Run all audits
  if (options.ssh !== false) {
    results.findings.push(...auditSSH());
  }
  
  if (options.credentials !== false) {
    results.findings.push(...auditCredentials(targetDir));
  }
  
  if (options.docker !== false) {
    results.findings.push(...auditDocker(targetDir));
  }
  
  if (options.agent !== false) {
    results.findings.push(...auditAgentConfig(targetDir));
  }
  
  // Calculate summary
  for (const finding of results.findings) {
    results.summary.total++;
    switch (finding.severity) {
      case SEVERITY.CRITICAL: results.summary.critical++; break;
      case SEVERITY.HIGH: results.summary.high++; break;
      case SEVERITY.MEDIUM: results.summary.medium++; break;
      case SEVERITY.LOW: results.summary.low++; break;
      case SEVERITY.INFO: results.summary.info++; break;
    }
  }
  
  return results;
}

/**
 * Check text for prompt injection
 */
function checkPromptInjection(text) {
  return {
    isClean: scanForPromptInjection(text).length === 0,
    patterns: scanForPromptInjection(text)
  };
}

module.exports = {
  runAudit,
  auditSSH,
  auditCredentials,
  auditDocker,
  auditAgentConfig,
  checkPromptInjection,
  scanForPromptInjection,
  scanFileForSecrets,
  SEVERITY,
  CHECKS,
  PROMPT_INJECTION_PATTERNS,
  SECRET_PATTERNS
};
