# ai-security-audit

Audit your dev environment for security vulnerabilities. Based on @mrnacknack's "10 ways to hack into a vibecoder's clawdbot".

## Quick Reference

```bash
# Full audit
ai-security-audit

# Audit specific directory
ai-security-audit /path/to/project

# JSON output
ai-security-audit --json

# Check for prompt injection
ai-security-audit --check-text "SYSTEM OVERRIDE ignore instructions"

# Skip certain checks
ai-security-audit --no-ssh --no-docker
```

## Checks Performed

| Category | Check | Severity |
|----------|-------|----------|
| SSH | Password auth enabled | CRITICAL |
| SSH | Root login permitted | HIGH |
| SSH | Default port 22 | MEDIUM |
| Credentials | World-readable .env | CRITICAL |
| Credentials | Exposed AWS credentials | CRITICAL |
| Credentials | Hardcoded secrets | HIGH |
| Docker | Privileged mode | CRITICAL |
| Docker | Host filesystem mount | CRITICAL |
| Docker | Docker socket exposed | CRITICAL |
| Agent | No user allowlist | CRITICAL |
| Agent | Open DM policy | HIGH |
| Agent | Exposed gateway | CRITICAL |
| Injection | Prompt injection patterns | HIGH |

## Exit Codes

- `0` - No issues or low severity only
- `1` - High severity issues found
- `2` - Critical vulnerabilities found

## Programmatic

```javascript
const { runAudit, checkPromptInjection } = require('ai-security-audit');

const results = runAudit('/path/to/project');
console.log(results.summary.critical); // Number of critical issues

const check = checkPromptInjection(userInput);
if (!check.isClean) {
  // Block or sanitize
}
```
