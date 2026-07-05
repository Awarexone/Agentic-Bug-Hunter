# Title: Local Privilege Escalation via Confluence Server

- **Platform**: Bugcrowd
- **Program**: Atlassian (Confluence Data Center)
- **Severity**: High (P3)
- **Date**: September 13, 2023
- **Researcher**: matcluck
- **Bounty**: $800

## Summary
A local privilege escalation vulnerability in Atlassian Confluence Data Center on Windows allowed an attacker with low-privilege access to escalate to Confluence administrator and NT AUTHORITY\SYSTEM by extracting secrets from a misconfigured configuration file.

## Technical Details
Confluence Server installation on Windows configured the `confluence.cfg.xml` file with insecure permissions. Located at `C:\Program Files\Atlassian\Application Data\Confluence\confluence.cfg.xml`, this file was readable by all members of the local Users group. The file contained database credentials in plaintext.

An attacker with a low-privilege foothold on the Windows host could:
1. Read the configuration file to extract database credentials
2. Use the credentials to access the Confluence database
3. Extract password hashes or modify data to escalate to Confluence administrator
4. Potentially leverage database access for further system compromise

## Steps to Reproduce
1. Gain low-privilege access to a Windows host running Confluence Server
2. Navigate to `C:\Program Files\Atlassian\Application Data\Confluence\`
3. Read the `confluence.cfg.xml` file
4. Extract database credentials (username, password, connection string)
5. Connect to the database using the extracted credentials
6. Escalate privileges within Confluence and potentially to SYSTEM

## Proof of Concept
```
C:\Users\lowpriv>type "C:\Program Files\Atlassian\Application Data\Confluence\confluence.cfg.xml"
<?xml version="1.0" encoding="UTF-8"?>
<confluence-configuration>
  <properties>
    <property name="hibernate.connection.username">confluence</property>
    <property name="hibernate.connection.password">PLAINTEXT_PASSWORD</property>
    <property name="hibernate.connection.url">jdbc:postgresql://localhost:5432/confluence</property>
    ...
  </properties>
</confluence-configuration>
```

## Impact
Complete compromise of the Confluence server including:
- Access to all Confluence data, pages, and attachments
- Confluence administrator privileges
- Potential escalation to NT AUTHORITY\SYSTEM
- Lateral movement within the corporate network

## Remediation
Atlassian fixed the issue by ensuring the `confluence.cfg.xml` file has proper ACLs that restrict read access to only the Confluence service account and local administrators.

## References
- https://bugcrowd.com/disclosures/a1086522-37fd-4162-89b2-64dec3b05ab2/local-privilege-escalation-via-confluence-server
