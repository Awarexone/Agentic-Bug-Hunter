# Title: Path Traversal Allowing Arbitrary File Access in AnythingLLM

- **Platform**: Protect AI (huntr)
- **Program**: mintplex-labs/anything-llm (Open Source Bug Bounty)
- **Severity**: High
- **Date**: 2024-07-15
- **Researcher**: huntr community member
- **Bounty**: Not disclosed

## Summary
A path traversal vulnerability was discovered in AnythingLLM (mintplex-labs/anything-llm), an open-source document chat application. The `normalizePath()` function could be bypassed using specially crafted paths, allowing attackers to read, delete, or overwrite critical files on the server, including the application's database and configuration files.

## Technical Details
The vulnerability existed in the path sanitization logic of AnythingLLM. The `normalizePath()` function was intended to prevent directory traversal attacks by blocking `../` sequences. However, a bypass was discovered using alternative encoding and path manipulation techniques. By crafting paths that passed the normalization check but still resolved to parent directories, an attacker could access files outside the intended storage directory.

## Steps to Reproduce
1. Send a request to the file-serving endpoint with a crafted path
2. The path bypasses the normalizePath() sanitization
3. The server reads or writes files outside the intended directory

## Proof of Concept
```
GET /api/workspace/../../etc/passwd HTTP/1.1
Host: anythingllm-instance.com
```
Alternative bypass using URL encoding:
```
GET /api/workspace/%2e%2e%2f%2e%2e%2fetc/passwd HTTP/1.1
```

## Impact
- Read or delete the application's SQLite database containing all chat history and settings
- Overwrite configuration files to inject malicious settings
- Access environment variables and API keys for LLM providers
- Complete compromise of the application's data
- Denial of service through deletion of critical files

## Remediation
- Use strict path validation that resolves paths to their canonical form before checking
- Implement an allowlist approach: only serve files from explicitly permitted directories
- Use `os.path.realpath()` or `pathlib.Path.resolve()` to resolve symlinks and parent references
- Run the application in a container with restricted filesystem access
- Apply the principle of least privilege to the application's file system access

## References
- https://huntr.com/bounties/38f282cb-7226-435e-9832-2d4a102dad4b
- https://protectai.com/threat-research/july-vulnerability-report
