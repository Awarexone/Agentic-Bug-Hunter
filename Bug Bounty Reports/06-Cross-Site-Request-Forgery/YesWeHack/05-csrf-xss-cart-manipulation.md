# Title: CSRF Leading to XSS via Product Cart Manipulation

- **Platform**: YesWeHack
- **Program**: European E-commerce Platform
- **Severity**: Medium
- **Date**: 2024
- **Researcher**: sahid-rahman
- **Bounty**: N/A

## Summary
A CSRF vulnerability was chained with stored XSS in a European e-commerce platform's cart functionality, allowing an attacker to execute arbitrary JavaScript in a victim's browser context.

## Technical Details
The e-commerce platform's add-to-cart endpoint lacked CSRF protection. Additionally, the product name field was vulnerable to stored XSS. By combining these two issues, an attacker could:
1. Create a product with a malicious JavaScript payload in the name field
2. Craft a CSRF PoC that adds this malicious product to any user's cart
3. When the victim views their cart, the XSS payload executes

The attack chain:
- CSRF bypass in `POST /cart/add` endpoint
- No input sanitization in product name field
- XSS fires when cart page renders the malicious product name

## Steps to Reproduce
1. Register as a seller on the platform
2. Create a new product with XSS payload in the name: `<img src=x onerror=alert(document.cookie)>`
3. Identify that the add-to-cart endpoint has no CSRF token
4. Craft an HTML page with an auto-submitting form that adds the malicious product
5. Host the page and send link to a victim
6. When victim visits and is logged in, the product is added to their cart
7. When victim views their cart page, the XSS payload executes

## Proof of Concept
```html
<html>
<body>
<form action="https://target.com/cart/add" method="POST">
<input type="hidden" name="product_id" value="MALICIOUS_PRODUCT_ID" />
<input type="hidden" name="quantity" value="1" />
<input type="submit" value="Submit" />
</form>
<script>document.forms[0].submit();</script>
</body>
</html>
```

## Impact
- Execution of arbitrary JavaScript in victim's browser
- Cookie theft and session hijacking
- Cart manipulation and unauthorized purchases
- Potential account takeover

## Remediation
The platform fixed the issue by:
1. Implementing CSRF protection on all cart endpoints
2. Adding proper input sanitization and output encoding for product names

## References
- https://medium.com/@sahid-rahman/csrf-leading-to-xss-via-product-cart-manipulation-on-a-bug-bounty-program-6dcb5edbadb9
