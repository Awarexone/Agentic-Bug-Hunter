# Title: $15,000 RCE Through Monitoring Debug Mode

- **Platform**: HackerOne
- **Program**: Private Program
- **Severity**: Critical
- **Date**: 2024-07-15
- **Researcher**: 0xold
- **Bounty**: $15,000

## Summary
A remote code execution was achieved by monitoring for debug mode activation on a web application. The researcher set up automated monitoring to catch when developers accidentally enabled debug mode in production, revealing detailed error messages that led to LFI and ultimately RCE.

## Technical Details
The researcher was testing an application and noticed that debug mode was briefly enabled, showing detailed error responses. The developer quickly disabled it, but the researcher realized they could monitor endpoint responses for size changes to detect when debug mode was re-enabled.

Using a monitoring script, the researcher watched for response size changes on error endpoints. When debug mode was re-enabled, the larger error responses revealed that the application dynamically included files based on a `Model` parameter and called methods based on a `method` parameter. This was a Local File Inclusion (LFI) vulnerability.

The LFI allowed including arbitrary files, but initial exploitation was limited. The researcher found a path where request headers were written to a file (`test.txt`). By sending a request to `X-ORIGINAL_URL` with a webshell in the header, the content was written to `test.txt`. Then, the LFI was used to include this file, triggering the webshell.

## Steps to Reproduce
1. Monitor the target for debug mode activations (response size changes)
2. When debug mode enables, capture error responses
3. Identify the vulnerable `Model` and `method` parameters
4. Fuzz the web directory to discover writable paths
5. Find that request headers are written to `test.txt`
6. Send a request with a webshell in the HTTP header to `X-ORIGINAL_URL`
7. Access `test.txt` via the LFI to execute the webshell

## Proof of Concept
Monitoring script:
```bash
watch -n 5 'curl -s -o /dev/null -w "%{size_download}" https://target.com/error -H "Model: test"'
```

When response size increased (debug on), the error revealed:
```
Include: /var/www/includes/{Model}.php
Method: {method}()
```

Webshell injection via header:
```
GET / X-ORIGINAL_URL: /error
Header: User-Agent: <?php system($_GET['cmd']); ?>
```

Then executing: `/error?Model=../../../../var/www/test&cmd=id`

## Impact
- Remote code execution on the production server
- Access to environment variables and secrets
- Potential database access
- Full server compromise
- Pivot point for internal network attacks

## Remediation
1. Disable debug mode in production environments
2. Remove the `Model`/`method` dynamic inclusion pattern
3. Implement proper access controls for error pages
4. Remove the `test.txt` file logging mechanism
5. Sanitize file headers before writing to disk

## References
- https://medium.com/@0xold/15k-rce-through-monitoring-debug-mode-4f474d8549d5
