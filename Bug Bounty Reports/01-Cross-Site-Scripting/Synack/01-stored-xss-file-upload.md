# Title: Stored Cross-Site Scripting via Malicious Excel File Upload on Cloud Dashboard

- **Platform**: Synack
- **Program**: Cloud Network Management Platform
- **Severity**: High
- **Date**: June 2023
- **Researcher**: Octavian Mihail Romanescu (octa-mihail)
- **Bounty**: $500

## Summary

A stored Cross-Site Scripting (XSS) vulnerability was discovered in a cloud-based network management dashboard. The application allowed administrators to bulk-onboard network devices by uploading `.csv` or `.xlsx` files containing device serial numbers and IDs. User-supplied data within uploaded spreadsheet files was rendered unsanitized in the browser, allowing arbitrary JavaScript execution in the context of other administrative users viewing the onboarded device list.

## Technical Details

The target application was a dashboard for managing cloud-controlled network elements (similar to Cisco Meraki). It featured a device onboarding module where administrators could upload Excel (`.xlsx`) or CSV (`.csv`) files to register multiple devices at once. The system would parse the uploaded file, extract device information, and display the imported records in a web-based device management table.

The vulnerability existed because the application did not sanitize or encode cell values from the uploaded spreadsheet before rendering them as HTML content in the dashboard interface. By embedding an XSS payload into a spreadsheet cell, the payload would be stored server-side and executed in the browsers of any administrator who viewed the device list.

## Steps to Reproduce

1. Log in to the Synack target dashboard as an authenticated user
2. Navigate to the device onboarding/import section
3. Create a new Excel (`.xlsx`) file with two columns: "Device Serial" and "Device ID"
4. In the "Device Serial" field, enter the following payload: `<img src=x onerror=alert(document.domain)>`
5. Save the Excel file and upload it through the onboarding interface
6. Navigate to the device management list where imported devices are displayed
7. Observe that the JavaScript payload executes, showing `alert(document.domain)`

## Proof of Concept

The Excel file was crafted with the following cell content:

| Device Serial | Device ID |
|---------------|-----------|
| `<img src=x onerror=alert(document.domain)>` | SN-12345 |
| AP-67890 | `javascript:alert(1)` |

The spreadsheet was uploaded via the standard file upload form using a `multipart/form-data` POST request. The server-side parser extracted the cell contents and stored them in a database without sanitization. When the device list page was loaded, the application rendered the device serial field directly into the DOM without HTML encoding.

```http
POST /api/device/import HTTP/1.1
Host: dashboard.target.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="devices.xlsx"
Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet

[BINARY EXCEL FILE WITH XSS PAYLOAD]
------WebKitFormBoundary--
```

## Impact

An attacker could craft a malicious spreadsheet that, when uploaded and viewed by other administrators, would execute arbitrary JavaScript in their browsers. This could be leveraged to:
- Steal session cookies for account takeover
- Perform administrative actions on behalf of the victim
- Exfiltrate sensitive data displayed on the dashboard (API keys, network configurations, customer data)
- Deploy ransomware-like defacement across the management console

Since administrative users typically have elevated privileges, a successful stored XSS attack could lead to full compromise of the cloud management platform.

## Remediation

The vendor implemented proper output encoding for all user-supplied data rendered in the browser. Specifically:
- HTML entity encoding was applied to device serial numbers, IDs, and any other fields parsed from uploaded files
- Server-side validation was added to reject spreadsheet cells containing HTML tags or JavaScript URIs
- Content Security Policy (CSP) headers were configured to restrict script execution

## References
- https://octa-mihail.medium.com/my-first-bounty-on-synack-red-team-4ef53329c960
