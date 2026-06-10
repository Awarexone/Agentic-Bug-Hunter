# Browser JS Request-Signing Workflow (Reference)

Detail companion to the `client-reverse` skill. Use when the blocker is browser-side: sign generation, token flow, cookie hops, worker/wasm indirection, anti-bot logic, or a browser-vs-local execution divergence.

The whole point for a bounty hunter: reproduce one signed request **outside** the client so you can fuzz the protected API for IDOR / auth / business-logic. The signing weakness alone is N/A — the downstream bug pays.

---

## Mission: stay on the staged spine

```
intake -> evidence -> locate -> recover -> runtime -> validation -> replay
```

Pick the next step from **engineering state**, not from clue words. Seeing the string `sign` does not put you in `recover` — you are in `locate` until you can point at the writer line.

## Intake contract

Fill this before touching Sources:

```text
Target page / endpoint:
Target request / field / cookie / message:
Trigger action:
Current symptom (401 invalid sign / 403 bot / encrypted body):
Known evidence:
Goal (which protected API am I trying to reach to fuzz?):
Constraints (scope, rate limit, anti-bot in play):
```

Then answer: is the target request real or guessed? Is the write boundary proven? Is the blocker shell opacity, runtime divergence, or just freshness proof?

## Evidence rule (do this before any reversing)

Capture a real sample and run the packet-first gate:

1. Replay the captured request UNCHANGED -> 200? It isn't signed. Stop reversing, go fuzz.
2. Replay 5 min later -> still 200? No freshness check = replay-window bug (report it).
3. Mutate one non-signed field, keep the sign -> 200? Sign doesn't cover it. Tamper freely.
4. Only if mutation breaks it does the sign cover that field -> proceed to `locate`.

Keep a persistent request-chain record: request sample, sink/write boundary, upstream hops, runtime notes, replay prerequisites.

## Boundary model

```text
writer <- builder <- entry <- source
```

- **writer** — final write into body / header / query / cookie / WS envelope
- **builder** — transform / sign / encrypt / serialize / canonicalize
- **entry** — UI action, callback, event, or response that starts the chain
- **source** — upstream response, storage, cookie, browser state, `Date.now()`, randomness, user input

Default order: capture a real sample -> observe the sink first -> walk backward writer<-builder<-entry<-source -> expand upstream when a source depends on a prior request -> split normal-state vs risk-state chains if both appear.

## Stage selection

### locate
Enter when the request / sink / write boundary / upstream chain is unproven. Own: where the value is finally written, which action triggers it, what upstream state feeds it. Stop when the next blocker is shell opacity or runtime divergence rather than request discovery.

**DevTools moves:** XHR/fetch Breakpoints (paste the endpoint path) -> walk the Call Stack up to the writer frame; `Ctrl+Shift+F` global search for the field name; `{}` pretty-print for stable line numbers; DOM event breakpoints for click-triggered sends.

### recover
Enter only after the boundary is real and the blocker is opacity. Typical shells: webpack bootstrap, worker bridge, wasm loader, dispatcher flattening, string tables, helper indirection, JSVMP. Reduce only the layer that blocks you. Stop as soon as you have a readable or callable signer contract. Prefer the black-box shortcut: capture `sign(input)->output` pairs or call the page's own signer; you rarely need the crypto math.

### runtime
Enter when boundary and shell are clear but browser-exec and local-exec diverge. Classify the FIRST divergence before patching: missing object, missing state, anti-debugging, unstable source, risk branch. Keep the runtime dependency set minimal.

### validation
Enter when the remaining work is equivalence proof. Compare checkpoints, not just the final output: request body before sign, sign input tuple, sign output, encrypted payload, header set, cookie/storage mutation. The two usual breakers: JSON key ordering / separators, and field concatenation order. Diff the pre-hash message string, not the output hash.

### replay
A Burp/Python baseline you can mutate. Do not enter Burp fuzzing until you can explain: where the field is written; which inputs are stable constants; which come from cookies/storage/upstream/lifecycle; whether order/navigation state matters; which fields are safe to mutate.

## Input classification (the decision that gates everything)

| Input | Mutable by you? | Meaning |
|---|---|---|
| timestamp | yes | regenerate per replay; check validity window |
| nonce / requestId | yes | generate fresh; check server uniqueness enforcement |
| deviceId / uuid | yes (pin one) | usually constant per session |
| body / path | yes | the prize — re-sign to fuzz IDOR / mass-assignment |
| secret key | no (extract it) | if baked into JS/APK -> forge any request offline |

If the secret is server-side and the signer is uncallable, you may only replay unchanged requests — then test whether the sign omits the path/body (forge anyway) or never expires (replay-window bug).

## Topic routing inside the browser branch

| Blocker | Lens |
|---|---|
| sign / token / dynamic headers / encrypted fields | crypto-entry locating + boundary observation |
| worker / wasm / webpack runtime / loader callbacks | bridge + shell reduction |
| endless `debugger`, branch flips, `hasDebug` | anti-debug + runtime diagnosis |
| cookie hops, WebSocket, protobuf, SSE, ack/renewal | protocol + state-chain expansion |
| browser/local mismatch, missing browser state | minimal environment fit (or use a headless bridge) |

## Tool order

1. **DevTools / Burp / mitmproxy** — capture the real request and its initiator
2. **DevTools Sources + console hooks** — trace boundary, de-shell, log sign(input)->output
3. **Python `requests` (or headless bridge)** — replay, then fuzz the protected API

No special MCP tooling is required — these are all standard.

## Handoff discipline

Whenever the stage changes, emit a compact card. Do not carry guesses forward as facts:

```text
--- Stage Handoff ---
From: {previous}
To:   {next}
Proven: {request, boundary, upstream chain, runtime/recovery facts}
Open:   {questions the next stage must answer}
Invalidated: {stale assumptions or "none"}
```

## Replay exit criteria

Reproduce one signed request outside the client, then immediately pivot to the bug hunt on the now-reachable endpoint: IDOR, Broken Auth / Access Control, Mass Assignment, Business Logic (see `web2-vuln-classes`). Validate the downstream finding with the 7-Question Gate before writing anything. The signature reversal is the means; the access-control or logic bug behind it is the report.
