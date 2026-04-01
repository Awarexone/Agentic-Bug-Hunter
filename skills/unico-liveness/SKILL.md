# Unico IDTech — Liveness Bypass Testing

**Program**: Unico IDTech (HackerOne)
**Scope**: Biometric liveness detection engine (SDK)
**Primary reward**: up to $10,000 for critical liveness bypass

---

## CRITICAL: SDK vs Wrapper App

```
IN SCOPE:  The biometric capture and processing ENGINE (SDK)
OUT OF SCOPE: The test wrapper applications (the app UI/shell)

You are testing the SDK's liveness logic, not the app's buttons or layout.
```

---

## Setup

### Web Testing (easiest starting point)
```
URL: https://sdk-h1.unico.io/
Modern browser with camera access
No TTL — web app does not expire
```

### Mobile Testing (native preferred)
```
Android Native / iOS Native — recommended (direct SDK integration)
Flutter — available but uses native SDK as bridge
Physical device REQUIRED — emulators/simulators do NOT work
Android 6.0 (API 23)+ / iOS 14.0+
TTL: 30 days — re-download at https://sdk-h1.unico.io/mobile-sdks if expired
```

### Required Headers (add to all web requests)
```http
X-HackerOne-Research: YOUR_H1_USERNAME
User-Agent: YOUR_H1_USERNAME
```

---

## How to Capture Transaction ID + Process ID

**These are MANDATORY in every liveness bypass report.**

### Web SDK
1. Open DevTools → Network tab
2. Trigger a liveness capture
3. Look for the response from the SDK API call
4. Find `transactionId` and `processId` in the JSON response body

### Mobile SDK (Android)
```java
// In the SDK callback:
UnicoCheckResult result = ...;
String transactionId = result.getTransactionId();
String processId = result.getProcessId();
```

### Mobile SDK (iOS)
```swift
// In the delegate callback:
func onSuccessSelfie(result: SelfieResult) {
    let transactionId = result.transactionId
    let processId = result.processId
}
```

---

## Matrix 1: Presentation Attack Detection

Test whether the engine accepts a non-live presentation as live.

| Attack Type | Report When | Threshold |
|---|---|---|
| **Photo Attack** | Engine accepts static image as live | Bypass rate >1% over 100 attempts |
| **Video Replay** | Engine accepts pre-recorded video | Bypass successful on 3+ different samples |
| **3D Mask/Model** | Engine accepts non-human presentation | Any high-quality mask achieves >5% success rate |
| **Deepfake** | Engine accepts synthetic video stream | Real-time bypass achieved with <500ms latency |

### Photo Attack Testing
```
1. Use a high-res photo of the target face (printed or on screen)
2. Present to the camera during liveness capture
3. Try: flat print, curved print, phone screen, tablet screen
4. Track attempts — document bypass rate (successes / total attempts)
5. Report if: bypass rate > 1% across 100 attempts
```

### Video Replay Testing
```
1. Record a genuine liveness capture session (screen recording or camera capture)
2. Replay the video in front of the camera during a new session
3. Try: phone screen, monitor, printed QR loop
4. Test on 3+ different face samples
5. Report if: bypass successful on 3+ samples
```

### 3D Mask/Model Testing
```
1. Use a 3D-printed or modeled face representation
2. Present during liveness capture
3. Try: realistic silicone masks, rigid 3D prints, mannequin heads
4. Track bypass rate across attempts
5. Report if: any high-quality mask achieves >5% bypass rate
```

### Deepfake Testing
```
1. Generate a real-time deepfake stream (using FaceSwap, DeepFaceLive, etc.)
2. Use a virtual camera to pipe the stream to the SDK
3. Measure total latency from source to acceptance
4. Report if: bypass achieved AND processing latency <500ms
```

---

## Matrix 2: Processing Integrity

Test whether modifying engine internals or input data causes it to accept forged input.

| Attack Type | Report When | Threshold |
|---|---|---|
| **Memory Manipulation** | Modified engine parameters accepted | Persistence across engine restarts |
| **Template Injection** | Artificial template processed as valid | Bypass works on multiple formats |
| **Timing Attacks** | Processing bypassed through race condition | Reproducible >50% of attempts |

### Memory Manipulation Testing
```
1. Intercept SDK in memory (using Frida, objection, or similar)
2. Modify liveness decision parameters at runtime
3. Attempt to force a positive liveness result
4. Restart the engine — test if modification persists
5. Report if: bypass persists across engine restarts
```

### Template Injection Testing
```
1. Intercept biometric template data sent to/from the SDK
2. Inject a crafted or replayed template
3. Test with multiple template formats
4. Report if: forged template accepted on multiple formats
```

### Timing Attack Testing
```
1. Identify asynchronous operations in the SDK processing flow
2. Attempt to inject a bypass during race window
3. Test consistently: track success rate over attempts
4. Report if: bypass reproducible >50% of attempts
```

---

## Matrix 3: Data Flow Integrity

Test whether intercepted or replayed biometric data can be reused.

| Attack Type | Report When | Threshold |
|---|---|---|
| **Capture Relay** | Reused biometric data accepted | Bypass works across different sessions |
| **Stream Manipulation** | Modified data stream processed as valid | Manipulation undetected by engine |
| **Session Hijacking** | Auth state transferred between instances | State can be copied between instances |

### Capture Relay Testing
```
1. Complete a successful liveness capture (keep the captured data/token)
2. Start a new session
3. Replay the captured biometric data in the new session
4. Report if: reused data accepted in a different session
```

### Stream Manipulation Testing
```
1. Intercept the video/biometric stream between camera and SDK
2. Modify the stream (inject frames, modify metadata, alter signal)
3. Present the modified stream to the SDK
4. Report if: manipulation is not detected and engine returns positive
```

### Session Hijacking Testing
```
1. Complete a liveness capture and capture the session state/tokens
2. Attempt to copy the authentication state to a new instance/browser
3. Report if: copied state accepted as a valid liveness confirmation
```

---

## Intercept Tools Setup

### Web SDK — Browser Proxy
```bash
# Route browser through Burp Suite
# In Burp: Proxy → Options → Listen on 8080
# Browser: set proxy to 127.0.0.1:8080
# Use Burp's CA cert to intercept HTTPS

# Watch for SDK API calls — usually to a *.unico.io endpoint
```

### Mobile SDK — Android (Frida)
```bash
# Install Frida server on device
adb push frida-server /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &

# List running processes
frida-ps -U

# Hook the liveness decision function
frida -U -n com.unico.testapp -l hook_liveness.js
```

### Mobile SDK — iOS (objection)
```bash
# Using objection (built on Frida)
objection -g com.unico.testapp explore

# List classes
ios hooking list classes | grep -i liveness
ios hooking list classes | grep -i unico

# Hook a method
ios hooking watch method "-[UnicoLiveness checkLiveness:]"
```

---

## Reporting a Liveness Bypass

### Gate: Is It Worth Reporting?

Before writing the report, verify ALL of the following:
- [ ] SDK returned a positive liveness result (not just the app failing)
- [ ] Bypass meets the threshold for the attack type (see matrices above)
- [ ] You have Transaction ID from the successful bypass
- [ ] You have Process ID from the successful bypass
- [ ] Bypass is reproducible (document exact reproduction steps)

### Report Template

```markdown
**Title**: [Attack Type] Bypass in Unico Liveness SDK — [brief description]
Example: "Video Replay Bypass in Unico Liveness SDK allows pre-recorded video to pass liveness check"

**Transaction ID**: [from successful bypass attempt]
**Process ID**: [from successful bypass attempt]

**Summary**:
The Unico liveness detection engine accepts [attack input] as a valid live biometric capture.
An attacker can bypass identity verification by [specific method].

**Environment**:
- Platform: [Web / Android / iOS]
- Device: [model + OS version if mobile]
- SDK version: [version from app or DevTools]
- Test app: [URL or version]

**Steps to Reproduce**:
1. [Exact setup]
2. [Exact attack setup]
3. [Exact steps to trigger bypass]
4. [What to observe — SDK returns positive result]

**Evidence**:
- Video recording of the bypass (required)
- Screenshot of positive liveness result with Transaction ID visible
- Bypass rate: [X successes / Y attempts]

**Impact**:
An attacker can impersonate another user's identity verification, bypassing biometric controls that protect [specific use case — account creation, KYC, transaction authorization].

**Severity**: [Critical/High/Medium/Low] per liveness bypass matrix:
- Critical ($10,000): [explain why — e.g., real-time deepfake with <500ms latency]
```

---

## CVSS for Liveness Bypasses

```
Photo Attack:        CVSS 7.5–8.5 (High)   — requires physical/digital photo
Video Replay:        CVSS 7.5–8.5 (High)   — requires recorded video
3D Mask:             CVSS 8.5–9.5 (Critical) — harder to detect, scales
Deepfake <500ms:     CVSS 9.0–10.0 (Critical) — real-time, scalable
Memory Manipulation: CVSS 8.0–9.5 (Critical) — persistent bypass
Replay Across Sessions: CVSS 8.5–9.5 (Critical) — persistent bypass
```

---

## What NOT to Report

- Issues in the wrapper test app UI (out of scope)
- Bypasses that don't produce a positive liveness result from the SDK
- Bypasses below the threshold (e.g., <1% photo bypass rate)
- Theoretical bypasses without demonstrated success
- Issues requiring physical access to the victim's phone (out of scope — MITM excluded)
