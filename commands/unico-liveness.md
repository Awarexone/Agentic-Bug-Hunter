---
description: Test Unico IDTech liveness SDK for biometric bypass vulnerabilities. Walks through all 3 attack matrices (Presentation Attack, Processing Integrity, Data Flow Integrity). Usage: /unico-liveness [photo|video|deepfake|memory|relay|stream|session|all]
---

# /unico-liveness

Liveness bypass testing for the **Unico IDTech** biometric SDK.

## STOP: Pre-flight Checklist

Before starting, confirm:
- [ ] You have a test environment set up (web: https://sdk-h1.unico.io/ OR physical mobile device)
- [ ] Your H1 username is set in request headers (X-HackerOne-Research + User-Agent)
- [ ] You know how to extract Transaction ID and Process ID (check DevTools → Network or SDK callback)
- [ ] You are targeting the SDK engine — NOT the wrapper test app

## Usage

```
/unico-liveness              → shows all matrices and guidance
/unico-liveness photo        → photo attack checklist
/unico-liveness video        → video replay checklist
/unico-liveness deepfake     → deepfake bypass checklist
/unico-liveness memory       → memory manipulation checklist
/unico-liveness relay        → capture relay checklist
/unico-liveness stream       → stream manipulation checklist
/unico-liveness session      → session hijacking checklist
/unico-liveness all          → run all matrices in sequence
```

## Phase 1: Environment Setup (5 min)

### Web Setup
```bash
# Open in browser with camera access
open https://sdk-h1.unico.io/

# Open DevTools → Network tab → filter by "unico" or "sdk"
# Will show API calls to the SDK endpoint

# Set proxy to Burp Suite (optional but recommended for interception):
# Burp → Proxy → Options → Listener: 127.0.0.1:8080
# Browser → Settings → Proxy → 127.0.0.1:8080
```

### Mobile Setup (Android)
```bash
# Verify device is physical (not emulator)
adb devices

# Install Frida for hooking (optional)
adb push frida-server /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server
adb shell "/data/local/tmp/frida-server &"

# Route traffic through Burp
# Settings → WiFi → [Network] → Proxy → Manual → 192.168.x.x:8080
# Install Burp CA cert on device
```

### Capture Transaction ID + Process ID
```
Web:    DevTools → Network → find SDK API response → copy transactionId + processId from JSON
Android: SDK callback result.getTransactionId() + result.getProcessId()
iOS:     delegate method result.transactionId + result.processId
```

---

## Matrix 1: Presentation Attack Detection

### Photo Attack (threshold: >1% bypass / 100 attempts)
```
Setup:
1. Find or take a high-res frontal face photo
2. Try each presentation method:
   - Printed photo (flat)
   - Printed photo (curved around cylinder)
   - Photo on phone screen
   - Photo on tablet/monitor

Test loop (100 attempts total):
for i in {1..100}; do
    # Present the photo to the camera during capture
    # Record: pass / fail
    # Track: bypass_count / total
done

Report criteria: bypass_count/100 > 0.01 (>1% bypass rate)
Document: bypass_count, total_attempts, photo_type, device
```

### Video Replay (threshold: 3+ different samples)
```
Setup:
1. Record a genuine liveness capture on your own face (screen record or camera)
2. Test on 3+ different face/video samples

Replay methods to test:
- Phone screen playing video → held to camera
- Monitor displaying video → camera pointed at monitor
- Virtual camera (OBS + virtual cam) → piped to browser SDK

For each sample:
- Attempt replay during a new liveness capture session
- Note if SDK returns positive liveness result
- Capture Transaction ID on success

Report criteria: bypass successful on 3+ different samples
```

### 3D Mask/Model (threshold: >5% bypass rate)
```
Mask types to test:
- Rigid 3D-printed face mask
- Silicone/flexible mask
- Mannequin head
- Photo-realistic prosthetic

Test protocol:
- Present mask to camera during liveness capture
- Attempt 20+ times per mask type
- Track bypass rate per mask type

Report criteria: any mask achieves >5% bypass rate
```

### Deepfake (threshold: real-time bypass <500ms)
```
Tools: FaceSwap, DeepFaceLive, SimSwap, Rope
Virtual camera: OBS (Windows/Mac), v4l2loopback (Linux)

Setup:
1. Run deepfake pipeline on target face
2. Output to virtual camera
3. Select virtual camera as input in SDK capture

Measure latency:
- Time from face presentation → SDK positive decision
- Must be <500ms total

Report criteria: bypass achieved AND latency < 500ms
```

---

## Matrix 2: Processing Integrity

### Memory Manipulation (threshold: persists across engine restarts)
```
Tools: Frida, objection, memory editors (GameGuardian on Android)

Target functions to find:
frida-ps -U   # list processes
# Hook Unico SDK classes:
frida -U -n [app_package] -e "
  Java.perform(function() {
    var classes = Java.enumerateLoadedClassesSync();
    classes.filter(c => c.includes('unico') || c.includes('Liveness')).forEach(console.log);
  });
"

# Find and hook liveness decision method
# Attempt to force positive return value
# Restart the engine (close/reopen app)
# Test if modification persists after restart

Report criteria: bypass persists across engine restarts
```

### Template Injection (threshold: multiple formats)
```
1. Intercept biometric template transmission (via Burp or Frida)
2. Capture a valid template from a successful real capture
3. Modify and replay the template in a new session
4. Try: JSON field injection, base64 manipulation, binary modification

Test across multiple template formats if SDK supports them
Report criteria: forged template accepted on 2+ formats
```

### Timing Attack (threshold: >50% success rate)
```
1. Profile SDK processing time (DevTools timing or Frida timestamp hooks)
2. Identify async operations or state transitions
3. Attempt to inject bypass during the race window
4. Test 20+ times, track success rate

Report criteria: bypass reproducible on >50% of attempts
```

---

## Matrix 3: Data Flow Integrity

### Capture Relay (threshold: works across sessions)
```
1. Complete a genuine liveness capture → capture the HTTP request/response
2. Note all tokens, biometric data, session identifiers in the captured request
3. Start a NEW session (new browser tab / new app session)
4. Replay the captured biometric data/request in the new session
5. Test: same user, different user, different device

Report criteria: captured data accepted in a different session
```

### Stream Manipulation (threshold: undetected by engine)
```
1. Set up a proxy between camera and SDK (virtual cam + manipulation)
2. Inject frames into the video stream:
   - Inject static frames
   - Modify facial landmarks
   - Alter liveness challenge responses (if any)
3. Check if SDK detects the manipulation

Report criteria: modification accepted without detection by engine
```

### Session Hijacking (threshold: state copyable between instances)
```
1. Complete a successful liveness capture in Browser/Device A
2. Extract all session state: cookies, tokens, localStorage, sessionStorage
3. Copy state to Browser/Device B (different browser profile or device)
4. Test if Device B shows liveness as already completed

Report criteria: copied state accepted as valid liveness confirmation
```

---

## Writing the Report

When a bypass passes the threshold, document immediately:

```markdown
**Title**: [Attack Type] Bypass — [Unico Liveness SDK / Web/Android/iOS]
Example: "Video Replay Bypass in Unico Liveness SDK Web — 3/3 face samples bypassed"

**Transaction ID**: [REQUIRED — from successful bypass]
**Process ID**: [REQUIRED — from successful bypass]

**Environment**:
- Platform: Web (Chrome 120) / Android 13 (Pixel 7) / iOS 16 (iPhone 14)
- SDK version: [from DevTools or app build]

**Steps to Reproduce**:
1. [setup]
2. [attack execution — be exact]
3. [observation — SDK returns positive liveness]

**Evidence**:
- Screen recording (mandatory)
- Bypass rate: [X/Y attempts]
- Transaction ID screenshot

**Severity**: [with justification from matrix thresholds]
```

## Stop Signals (kill the lead if you see these)

- SDK consistently rejects the attack type across 20+ varied attempts
- Bypass only works on wrapper app behavior, not SDK decision
- You cannot reproduce the bypass consistently
- Success rate stays at 0% after trying 3+ attack variations
- Engine restart resets any modification (for memory attacks)
