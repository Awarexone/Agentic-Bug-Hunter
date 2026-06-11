---
name: client-reverse
description: 'Client-side request-signing and anti-bot token reversal for bug bounty — when a request carries a sign/sig/hmac/token/nonce/timestamp/X-Sensor header that Burp Repeater cannot replay, recover the signer just enough to reproduce the request outside the client. Packet-first staging (capture real request → prove replay works → only reverse if replay fails) across the locate→recover→runtime→validation→replay spine. Covers tracing backward from the signature field (writer→builder→entry→source), isolating user-mutable sign inputs (timestamp/nonce/deviceId/body) vs constants (secret key), hooking fetch/XHR in DevTools, JS deobfuscation basics (webpack/wasm/JSVMP), and the bounty payoff: reach the protected API to then hunt IDOR/auth/business-logic. Use when Burp/mitmproxy replay of a signed or anti-bot-gated request fails and you suspect a client-computed field is blocking you.'
---

# CLIENT-SIDE REQUEST-SIGNING / ANTI-BOT TOKEN REVERSAL

You hit a request you cannot replay. Burp Repeater returns `401 invalid signature` or `403 bot detected` even though the browser/app does it fine. There is a `sign`, `sig`, `X-Signature`, `_token`, `nonce`, `X-Acf-Sensor-Data`, or encrypted body the client computes. This skill recovers **just enough** of that signer to reproduce the request **outside** the client.

> **Why a bug bounty hunter cares:** the signature is not the bug. The signature is the **lock on the door**. Behind it is an API the program assumed only their own client would ever reach — so that API is often under-tested for IDOR, BOLA, mass assignment, and business logic. Reversing the signer is the cost of admission; the **payout** comes from what you fuzz once you're inside. Never report "I reversed your sign algorithm" as a finding on its own — that is N/A. Report the IDOR/auth bug you reached **through** it.

---

## THE CORE PRINCIPLE: PACKET-FIRST

> Reverse engineering is a **blocker-resolution step, not the default entrypoint.** Capture the real request first. Prove whether it already replays. Only reverse the signer if replay actually fails.

Most hunters waste hours decompiling JS for a "signature" that turns out to be replayable as-is, or gated by a timestamp that's valid for 5 minutes. Run this gate **before** opening DevTools Sources:

```
1. Capture the real request    (Burp/mitmproxy proxy, or DevTools → Network → Copy as cURL)
2. Replay it UNCHANGED          (paste cURL into terminal, or Burp Repeater)
   → 200 / works?  → IT'S NOT SIGNED. Skip all reversing. Go fuzz it.
3. Replay it again 5 min later  → still 200?  → no freshness check (replay window is wide/infinite)
4. Mutate ONE non-signed field  (e.g. change an `id` in the body, keep sign as-is)
   → 200?  → the sign does NOT cover that field → tamper freely, no reversing needed
   → 401?  → the sign covers it → NOW you reverse (continue to STAGES below)
```

Steps 2–4 alone kill ~half of "I need to reverse this" assumptions. A signature that omits the payload or endpoint, or never expires, is itself the bug — see the CoinMate pattern in **Real Paid Examples**.

---

## STAGE SPINE: locate → recover → runtime → validation → replay

Pick the stage from **engineering state**, not from clue words. "I see the word `sign`" does not mean you're in `recover`. You are in `locate` until you can point at the exact line that writes the signature.

```
intake → evidence → locate → recover → runtime → validation → replay
```

| Stage | Enter when... | Goal | Exit when... |
|---|---|---|---|
| **locate** | the signing function / write boundary is unproven | find where the sign field is written and what feeds it | you can point at writer ← builder ← entry ← source |
| **recover** | boundary is real but the code is obfuscated/opaque | de-shell only the layer blocking you (webpack/wasm/JSVMP) | you have a readable or callable signer contract |
| **runtime** | code is clear but browser-exec ≠ your-exec diverge | find the first divergence (missing object/state/anti-debug) | local run reproduces browser sign output |
| **validation** | remaining work is equivalence proof | match checkpoints, not just final output | sign(input) == observed for fresh inputs |
| **replay** | sign reproduces outside the client | Burp/Python baseline request you can fuzz | a stable request you can mutate for IDOR/auth |

Carry a one-line handoff between stages. Do not promote a guess to a fact:

```text
--- Stage Handoff ---
From: locate  To: recover
Proven: sign written at app.min.js:1, line ~4021; inputs = ts, nonce, JSON body, deviceId
Open:   builder is inside webpack module 5f3 behind a string-table — need to de-shell that one module
Invalid: assumption that deviceId was constant (it rotates per session)
```

---

## STAGE 1 — LOCATE: trace backward from the signature field

You know the **output** (the `sign` value on the wire). Walk backward to the **source**. Keep each layer distinct:

```text
writer  <-  builder  <-  entry  <-  source
```

- **writer** — the line that finally puts `sign` into the body/header/query/cookie/WS frame
- **builder** — the transform: `HMAC`, `MD5`, `AES`, sort-then-concat, `JSON.stringify` ordering
- **entry** — the UI action / callback / response that kicks off the chain
- **source** — what feeds the inputs: upstream response, localStorage, cookie, `Date.now()`, `crypto.getRandomValues`, user input

### Browser: find the writer in Chrome DevTools

```text
# 1. XHR/fetch breakpoint — break the moment the signed request fires
DevTools → Sources → XHR/fetch Breakpoints → + → paste the endpoint path (e.g. /api/order)
   trigger the action → execution pauses inside the request stack
   → walk UP the Call Stack panel: the frame that mutates headers/body is your writer

# 2. Search the bundle for the field name (catches the writer fast)
DevTools → Sources → Ctrl+Shift+F (search all loaded scripts)
   search: "sign"  "X-Signature"  ".sign ="  "headers["  "signature"
   click {} (pretty-print) on the minified file so line numbers are stable

# 3. DOM/event breakpoint when a click triggers it
DevTools → Elements → right-click the button → Break on → subtree/attribute modifications
```

### Strong first observation points (where to put the breakpoint)

| Sink (where sign lands) | First place to prove |
|---|---|
| request body field | final `JSON.stringify` / submit / `fetch(body=...)` |
| request header | the `headers[...] =` or `setRequestHeader` call |
| JS-set cookie | the `document.cookie =` setter |
| WebSocket frame | the final envelope object right before `ws.send(...)` |
| anti-bot blob (`X-Sensor-Data`, `_px`) | the SDK `init()` and the getter that returns the blob |

**Do NOT** broad-deobfuscate before the boundary is real. Keyword hits are not proof — many bundles ship `sign` strings that never run.

---

## STAGE 2 — RECOVER: de-shell only what blocks you

Enter only after the boundary is proven and the **only** remaining blocker is that the code is unreadable. Reduce the **single** layer in your way — never the whole bundle.

| Shell you hit | What it means | Minimal move |
|---|---|---|
| webpack bootstrap | modules wrapped in `__webpack_require__` | break inside the target module, read the local closure — don't unpack the whole bundle |
| string-array obfuscation | `_0x4a2b[12]` lookups | in console, print the decoder array; or set a breakpoint and read decoded values live |
| worker / `postMessage` bridge | sign runs in a Web Worker | breakpoint the worker script; treat `postMessage` payload as the contract |
| wasm loader | sign math compiled to wasm | hook the JS↔wasm boundary; capture inputs/outputs rather than decompiling wasm |
| JSVMP (custom bytecode VM) | a dispatcher loop interpreting bytes | **do not** reverse the VM — go runtime: hook inputs+output and treat sign as a black box |

> **The black-box shortcut beats decompilation 90% of the time.** You almost never need to understand the HMAC math. You need the **input tuple** and a way to **call the function**. Capture `sign(input) → output` pairs at runtime; if you can call the page's own signer, you never have to reimplement it.

### Reimplement vs reuse the page's signer

```javascript
// REUSE — if the signer is a reachable function, just call it from the console.
// Works when the page exposes it or you grab a reference at a breakpoint.
window.__sign = signFn;                 // assign at a breakpoint inside the builder
window.__sign({id: 999, ts: Date.now()})// → get a valid sig for ANY payload you want

// HOOK to log every real sign(input)->output the app produces (no reimplementation):
(function(){
  const orig = CryptoSigner.prototype.sign;        // adapt to the real object/method
  CryptoSigner.prototype.sign = function(...a){
    const out = orig.apply(this, a);
    console.log('SIGN', JSON.stringify(a), '=>', out);  // copy pairs for offline replay
    return out;
  };
})();
```

---

## STAGE 3 — ISOLATE THE INPUTS (the part that decides if replay is even possible)

For every input to the signer, classify it. This is the **whole game** — it tells you what you can mutate and whether you even need the secret.

| Input | Type | Attacker-mutable? | Implication |
|---|---|---|---|
| `timestamp` / `ts` | per-request | yes (you set it) | fine — regenerate per replay; check the validity window |
| `nonce` / `requestId` | per-request random | yes | fine — generate fresh; check if server enforces uniqueness (replay protection) |
| `deviceId` / `uuid` | per-session | yes (one value, reusable) | grab once, pin it — usually constant for your session |
| request **body** / **path** | per-request | yes | **the prize** — if sign covers it, you mutate body + re-sign to fuzz IDOR/mass-assignment |
| **secret key** / `appSecret` | constant, baked in | **no (you extract it)** | if it's in the JS bundle / APK, extraction = full forge ability for any request |

```text
DECISION:
  secret is in the client (hardcoded in JS or APK strings)
      → you can re-sign ANY request offline → full replay, fuzz everything
  secret is server-side only, but you can call the page's signer function
      → you can sign any payload while the page is open → replay via headless browser bridge
  secret is server-side AND signer is uncallable (heavy anti-debug)
      → you may only replay UNCHANGED requests
      → then test: does the sign omit the path/body? (CoinMate pattern) → forge anyway
      → does it never expire? → replay-window bug, report that
```

Hunt the bundle for a baked secret before doing anything clever:

```bash
# Pull the JS and grep for the secret feeding the signer
wget -q -r -l1 -A '*.js' -P /tmp/js/ "https://target.com" 2>/dev/null
grep -rnoE "appSecret|secretKey|signKey|HMAC|hmac|['\"][A-Za-z0-9+/]{24,}={0,2}['\"]" /tmp/js/ | head
# Cross-reference with /secrets-hunt --js-bundle for entropy-scored hits
```

---

## STAGE 4 — RUNTIME & VALIDATION: prove your sign == the app's sign

If you reimplemented the signer in Python, prove equivalence on a **fresh** input before trusting it. Compare checkpoints, not just the final byte:

```python
import hmac, hashlib, json, time

def sign(body: dict, ts: str, nonce: str, secret: bytes) -> str:
    # Reproduce the EXACT canonicalization the JS does — order, separators, encoding.
    # Get these by reading the builder, NOT by guessing.
    payload = json.dumps(body, separators=(',', ':'), sort_keys=False)  # JS JSON.stringify keeps INSERTION order, not sorted — set sort_keys=True ONLY if the builder explicitly sorts keys
    msg = f"{ts}{nonce}{payload}".encode()                            # match JS concat order!
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()

# VALIDATE: feed an input you captured from the browser, compare to the observed sig.
# checkpoints that must each match: canonical body string → message tuple → final digest
assert sign(captured_body, captured_ts, captured_nonce, SECRET) == observed_sig
```

The two killers are almost always **(a)** JSON key ordering / separator whitespace, and **(b)** concatenation order of the input fields. If your digest is wrong, diff the **pre-hash message string** against the one the app builds (log it at a breakpoint), not the output hash.

---

## STAGE 5 — REPLAY: build the request you'll actually fuzz

You are ready only when you can answer all five:

```
[ ] where is the signed field written?
[ ] which inputs are constants (secret, deviceId) vs per-request (ts, nonce, body)?
[ ] which inputs come from upstream responses / cookies / storage / page lifecycle?
[ ] does request ORDER or session STATE matter (does a prior call seed the nonce)?
[ ] which fields can I mutate and still produce a valid sign?
```

Then drive it from Python so you can fuzz at scale:

```python
import requests, time, uuid

SECRET = b"extracted_from_bundle"          # or call the page's signer via a headless bridge
DEVICE = "pinned-session-device-id"

def signed_request(body):
    ts = str(int(time.time()*1000))
    nonce = uuid.uuid4().hex
    sig = sign(body, ts, nonce, SECRET)    # your validated signer from Stage 4
    return requests.post("https://target.com/api/order",
        json=body,
        headers={"X-Timestamp": ts, "X-Nonce": nonce, "X-Signature": sig,
                 "X-Device-Id": DEVICE})

# NOW the bug hunt begins — mutate the body to reach the protected logic:
for victim_id in range(1000, 1100):        # IDOR sweep behind the signature
    r = signed_request({"orderId": victim_id})
    if r.status_code == 200 and "not authorized" not in r.text:
        print(f"IDOR: read order {victim_id}", r.json())
```

> Bridge option when the secret is server-side: keep a headless browser open, expose the page's own `sign()` via a tiny local HTTP shim, and have your Python fuzzer call out to it per request. You never reimplement crypto — the app signs for you.

---

## ANTI-BOT TOKENS (Akamai / DataDome / PerimeterX / hCaptcha-style)

Same spine, harder shell. These ship an SDK that emits an opaque sensor blob (`X-Acf-Sensor-Data`, `_px`, `datadome` cookie). Two realistic paths for a bounty hunter:

- **Reuse, don't reverse.** Grab one fresh valid token from a real browser session and replay it within its (short) validity window. Enough to prove an authenticated/protected endpoint is reachable and then demonstrate IDOR/auth there. You usually do **not** need to generate tokens at scale to prove one bug.
- **Headless bridge.** Drive a real browser (Selenium/Playwright) to mint the token, hand it to your Python fuzzer. Standard tooling, no SDK reversing.

> Full reversal of Akamai v3 sensor-data (PRNG-shuffled, file-hash + cookie-hash seeded) or PerimeterX's compiled SDK is a week-long research effort — **out of scope for a single bounty.** If the anti-bot itself is misconfigured (token never expires, token from `accountA` validates `accountB`'s requests, the protected endpoint is also reachable on a sibling host with no anti-bot), report **that** — it's a real finding without reversing anything. See the Stack→sibling-host idea in `web2-recon`.

---

## WHAT'S SUBMITTABLE vs N/A

| Finding | Verdict |
|---|---|
| "I reversed your client signing algorithm" | **N/A** — not a vuln by itself |
| Signed request replays unchanged forever (no timestamp/nonce freshness) | **Low/Medium** — replay-attack window; report it |
| Sign omits endpoint/payload → forge requests without the secret (CoinMate pattern) | **Medium/High** — request forgery |
| Secret key hardcoded in JS bundle / APK → forge any request | **Medium** alone; **High/Critical** chained to the API you unlock |
| Reached a protected API via reversed sign → **IDOR / BOLA / mass assignment** found there | **High/Critical** — the real prize; report the downstream bug |
| One user's anti-bot token validates another user's request | **Medium** — broken token binding |

> The deliverable is almost never the signing weakness. It is the **access-control or business-logic bug on the endpoint the signature was guarding.** Reach it, then run the IDOR / Broken Auth / Mass Assignment / Business Logic playbooks from `web2-vuln-classes`.

---

## TOOL MAP (standard tools — no special MCP needed)

| Need | Tool |
|---|---|
| capture the real request | Burp Suite proxy, or mitmproxy, or DevTools Network → Copy as cURL |
| break on the signed request | Chrome DevTools → Sources → XHR/fetch Breakpoints |
| read minified code | DevTools `{}` pretty-print + `Ctrl+Shift+F` global search |
| hook fetch/XHR / log sign() | DevTools console snippet (`Object.defineProperty` / method override) |
| grep bundle for the secret | `wget -r -A '*.js'` + `grep`, or `/secrets-hunt --js-bundle` |
| find hidden endpoints in JS | LinkFinder / jsluice (see `web2-recon`) |
| replay + fuzz at scale | Python `requests` (Stage 5 template) |
| mint anti-bot tokens | Selenium / Playwright headless bridge |
| mobile app variant (signer in APK) | `apktool` + `jadx` (static), `objection` / `frida` CLI (runtime hook) — same locate→recover→runtime→replay spine, packet-first |

> **Mobile note:** for an authorized Android app, the packet-first rule still wins — drive the app, watch Burp/mitmproxy, and only `jadx`/`frida` the APK when the packet is encrypted or unreplayable. Decompiling first is the rookie move.

---

## REAL PAID EXAMPLES

- **CoinMate API (HackerOne, disclosed)** — HMAC signature verification omitted the endpoint and payload, so requests could be forged that appeared legitimate without the correct secret (request forgery via incomplete signature coverage). This is the canonical "the sign doesn't actually cover what you'd mutate" win — find it with Stage 0 step 4.
- **Replay window on HMAC-SHA256 headers (API pentest pattern, disclosed write-ups)** — custom auth headers signed with HMAC but lacking timestamp/nonce freshness; captured valid requests replay hours/days later. Prove it with Stage 0 steps 2–3, no reversing required.
- **PerimeterX iOS SDK reversal (public research)** — compiled-to-ARM bot SDK reversed to a working token generator in ~1 week, disproving "compiled = unreverseable." Cited here as the realistic effort ceiling: pattern seen across anti-bot bypass research — for a single bounty, prefer token-reuse or a headless bridge over full SDK reversal.
- **Hardcoded HMAC secret in Android APK (mobile API pattern, disclosed write-ups)** — secret extracted from the APK lets an attacker sign arbitrary API requests, fully bypassing request validation. Find it with the Stage 3 bundle/APK secret grep.

> Cross-reference: once you're through the signature, run **IDOR**, **Broken Auth / Access Control**, **Mass Assignment**, and **Business Logic** from `web2-vuln-classes`; use `web2-recon` for hidden-endpoint and sibling-host discovery; validate with the 7-Question Gate before reporting.

See `references/browser-js-signing.md` for the full browser-JS staging detail, the boundary model, and handoff-card discipline.
