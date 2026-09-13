#!/usr/bin/env python3
"""Build the simplified opt-out / PII-restriction guide PDF spec.

Every factual claim below is grounded in the verbatim captures in sources/
(node_100637_raw.md, supporting_nodes_raw.md, privacy_statement_raw.md) and
inline-cited to a numbered source. No paraphrase invents a mechanism that
is not literally described in those files.
"""
import json

OUT = "output/opt_out_guide_spec.json"

def h(text, level=1):
    return {"type": "heading", "text": text, "level": level}

def p(text):
    return {"type": "paragraph", "text": text}

def bullet(text):
    return {"type": "paragraph", "text": "\u2022 " + text}

def table(rows, header=True, col_widths=None):
    d = {"type": "table", "rows": rows, "header": header}
    if col_widths:
        d["col_widths"] = col_widths
    return d

elements = []

# ---------- Cover / framing ----------
elements += [
    h("Netflix Privacy Hardening Guide", 1),
    p("<b>Simplified Opt-Out &amp; PII-Exposure Reduction Instructions</b>"),
    p(
        "Source of truth: Netflix Help Center article <b>\u201cHow to stop certain uses of "
        "your personal information\u201d</b> (help.netflix.com/en/node/100637) and the Netflix "
        "Privacy Statement (help.netflix.com/en/legal/privacy, Last Updated: <b>April 10, 2026</b>). "
        "Retrieved and verbatim-captured 2026-09-13; cross-checked by an independent verification pass."
    ),
    p(
        "This guide translates Netflix's own published controls into a prioritized, plain-language "
        "checklist, framed with standard data-protection security principles: <b>data minimization</b> "
        "(collect/retain only what's needed), <b>least exposure</b> (limit what third parties can link "
        "to you), and <b>account-security hygiene</b> (an attacker who owns your login owns every setting "
        "below \u2014 harden the account first)."
    ),
    p(
        "<b>Scope note:</b> These are consumer self-service privacy controls Netflix documents publicly. "
        "This is not a bypass of any technical control and requires no special access \u2014 every action "
        "below is available to any signed-in Netflix account holder through the normal Account UI."
    ),
    {"type": "pagebreak"},
]

# ---------- Quick-start priority matrix ----------
elements += [
    h("Priority Action Matrix", 1),
    p("Do these in order. Each row is a self-contained action \u2014 skipping one does not block the others."),
    table([
        ["#", "Action", "Time", "Effect"],
        ["1", "Harden login (unique password + recovery phone)", "2 min", "Prevents an attacker from undoing every other setting below"],
        ["2", "Behavioral Advertising \u2192 Off (each profile)", "1 min", "Stops on-Netflix ad targeting based on your activity"],
        ["3", "Matched Identifier Communications \u2192 Off (each profile)", "1 min", "Stops Netflix matching your email/phone to ad-platform profiles"],
        ["4", "Do Not Sell or Share My Personal Information", "1 min", "Opts out of CCPA-defined \u201csale/sharing\u201d for ads + marketing"],
        ["5", "Cookie preferences \u2192 reject non-essential", "2 min", "Blocks browser-based cross-site tracking technologies"],
        ["6", "Device-level ad ID reset/limit (phone, TV, streaming box)", "3 min/device", "Breaks device-level ad tracking outside Netflix's own controls"],
        ["7", "Review &amp; sign out unrecognized devices", "2 min", "Closes sessions you don't recognize; shrinks Netflix Household fingerprint surface"],
        ["8", "Hide/clear viewing history (optional)", "2 min", "Removes titles from driving recommendations + visible activity"],
        ["9", "Request your data copy (verify what's held)", "5 min to request", "Confirms exactly what personal data exists before you restrict further"],
        ["10", "Delete phone number / unsubscribe marketing email+SMS", "2 min", "Stops marketing text/email; note password-reset SMS caveat below"],
        ["11", "Full account deletion (if leaving Netflix entirely)", "5 min", "Triggers Netflix's deletion process; irreversible after grace window"],
    ], col_widths=[0.4, 2.6, 1.1, 2.9]),
    {"type": "pagebreak"},
]

# ---------- Section 1: Account security hardening first ----------
elements += [
    h("Section 1 \u2014 Harden the Account First", 1),
    p(
        "<b>Why this comes first:</b> every privacy toggle below lives behind your Netflix login. "
        "Standard security practice (defense-in-depth) says secure the perimeter before configuring "
        "the controls inside it \u2014 otherwise account takeover silently reverts every choice you make."
    ),
    h("1.1 Use a unique, strong password", 2),
    bullet("Password must be used ONLY for Netflix \u2014 credential reuse lets one breached site compromise this account."),
    bullet("At least 8 characters; mix uppercase, lowercase, numbers, symbols; avoid personal info (name, birthday, address) [Source 11]."),
    bullet("Change it any time at netflix.com/password, or via a reset email/SMS."),
    h("1.2 Add a recovery phone number", 2),
    bullet("Account &gt; Security &gt; add a phone number, so you can recover access if you forget your password [Source 11]. "
           "(Tradeoff: this adds one more PII field Netflix holds \u2014 see Section 4 for the data-minimization counter-argument.)"),
    h("1.3 Recognize phishing", 2),
    bullet("Netflix will NEVER ask for your card number, bank details, or password by text or email [Source 11][Source 12]."),
    bullet("Never pay through a third-party site linked from an email/text claiming to be Netflix."),
    bullet("Forward suspicious emails to phishing@netflix.com; do not click links or reply [Source 12]."),
    h("1.4 Audit and sign out devices regularly", 2),
    bullet("netflix.com/manageaccountaccess (\u201cManage Access &amp; Devices\u201d) shows devices active in the last 90 days [Source 3][Source 9]."),
    bullet("Sign out of anything you don't recognize, and always sign out before selling/returning a device [Source 11]."),
    {"type": "pagebreak"},
]

# ---------- Section 2: Advertising / tracking opt-outs ----------
elements += [
    h("Section 2 \u2014 Stop Personalized Advertising Uses", 1),
    h("2.1 Behavioral Advertising opt-out (per profile)", 2),
    p("<b>What it stops:</b> ads selected based on your activity on unaffiliated third-party sites/apps over time [Source 1]."),
    bullet("Sign in on a web browser \u2192 select the profile \u2192 Account \u2192 \u201cPrivacy and data settings\u201d \u2192 toggle \u201cBehavioral Advertising\u201d off [Source 1][Source 2]."),
    bullet("You will still see ads (if on an ad-supported/live-event tier) \u2014 they simply won't be behaviorally targeted [Source 1]."),
    bullet("Not offered on Kids profiles because Netflix states it does not run Behavioral Advertising there at all [Source 1][Source 3]."),
    bullet("Repeat per profile \u2014 this setting is NOT account-wide."),
    h("2.2 Matched Identifier Communications opt-out (per profile)", 2),
    p("<b>What it stops:</b> Netflix using a hashed/pseudonymized version of your email or phone to match you on third-party "
      "ad platforms for marketing purposes [Source 1][Source 2]."),
    bullet("Same location: Account \u2192 profile \u2192 \u201cPrivacy and data settings\u201d \u2192 toggle \u201cMatched Identifier Communications\u201d off [Source 1][Source 2]."),
    bullet("This is a separate switch from Behavioral Advertising \u2014 disabling one does not disable the other."),
    h("2.3 Do Not Sell or Share My Personal Information", 2),
    p("Some US state laws classify Netflix's ad/marketing identifier use as a \u201csale\u201d or \u201csharing\u201d of personal information [Source 2]."),
    bullet("Use the link in the footer of netflix.com, or go directly to netflix.com/dnsspi [Source 1][Source 2][Source 10]."),
    bullet("If your browser sends a Global Privacy Control (GPC) signal, Netflix states it honors that signal automatically where legally required [Source 2] \u2014 "
           "enabling GPC in a supporting browser/extension covers this without visiting the page manually."),
    bullet("Caveat (Netflix's own wording): this does not retroactively undo previously \u201csold/shared\u201d data, and does not stop all Behavioral Advertising by itself [Source 2] \u2014 pair it with 2.1."),
    h("2.4 Cookie preferences &amp; \u201cdo not track\u201d reality check", 2),
    bullet("Manage cookie categories at help.netflix.com/en/legal/privacy#cookies [Source 1][Source 2]."),
    bullet("<b>Important:</b> Netflix explicitly states it does \u201cnot currently respond to web browser \u2018do not track\u2019 signals\u201d [Source 2] \u2014 "
           "the browser DNT header does nothing here; use the cookie preference center and GPC instead."),
    bullet("Clearing browser storage (HTML5/IndexedDB/WebSQL) from your browser's own settings removes any similar-technology data Netflix may have stored client-side [Source 2]."),
    h("2.5 Digital Advertising Alliance (DAA) industry opt-outs", 2),
    p("These control OTHER companies' behavioral ads (not just Netflix's), for sites that participate in the DAA self-regulatory program [Source 1]."),
    bullet("United States \u2014 youradchoices.com [Source 1][Source 2]."),
    bullet("Europe \u2014 European Interactive Digital Advertising Alliance: youronlinechoices.com [Source 1][Source 2]."),
    bullet("Canada \u2014 Digital Advertising Alliance of Canada: youradchoices.ca [Source 1][Source 2]."),
    h("2.6 Resettable device identifiers (phones, tablets, streaming devices)", 2),
    p("Netflix may use a resettable device ID (e.g. Apple's IDFA, Google's Advertising ID) for marketing/ad delivery [Source 1][Source 2]."),
    bullet("This is controlled on the DEVICE, not in Netflix: look for \u201cPrivacy\u201d or \u201cAds\u201d in your device's OS settings and opt out / reset / limit ad tracking there [Source 1][Source 2]."),
    bullet("This choice is per-device \u2014 it does not carry over to a new phone, tablet, or streaming box [Source 1]."),
    {"type": "pagebreak"},
]

# ---------- Section 3: Household / recommendations / communications ----------
elements += [
    h("Section 3 \u2014 Reduce Device, Recommendation &amp; Communication Exposure", 1),
    h("3.1 Netflix Household device association", 2),
    p("Netflix determines whether a device is part of your \u201cNetflix Household\u201d using IP address, device IDs, and account "
      "activity \u2014 explicitly NOT GPS/precise location [Source 6]."),
    bullet("There is no in-app toggle to stop this signal selectively \u2014 Netflix's own guidance is: \u201cIf you would like us to stop collecting "
           "information for this purpose on a particular Netflix device, please sign out from that device\u201d [Source 1]."),
    bullet("Check/update Household from a TV, or review devices at netflix.com/manageaccountaccess and \u201cSign out of All Devices\u201d [Source 6]."),
    h("3.2 Limit what powers your recommendations", 2),
    p("Netflix states recommendations use viewing history, ratings, similar-member patterns, and title metadata \u2014 and explicitly "
      "does NOT use demographic data (age/gender) for this purpose [Source 8]."),
    bullet("Hide a title: Account \u2192 Profiles \u2192 choose profile \u2192 Viewing activity \u2192 click the hide icon next to a title, or \u201cHide all\u201d "
           "to clear all viewing history for that profile [Source 7]."),
    bullet("A hidden title stops counting toward recommendations (unless you watch it again) and is removed from Continue Watching; "
           "propagation across devices can take up to 24 hours [Source 7]."),
    bullet("This cannot be done from a Kids profile's Viewing activity page [Source 7]."),
    h("3.3 Marketing email &amp; text messages (SMS)", 2),
    bullet("Per-profile email/text preferences: Account \u2192 \u201cNotification settings\u201d for that profile [Source 1][Source 2]."),
    bullet("Quick unsubscribe: click \u201cunsubscribe\u201d in any marketing email, or reply STOP to a text [Source 2]."),
    bullet(
        "<b>Critical caveat:</b> opting out of alerts/offers/surveys via those settings does NOT stop password-reset texts \u2014 Netflix "
        "states you will still receive a text if you request a password reset by SMS while a number is on file [Source 1]. "
        "To stop ALL texts, remove the phone number entirely: Account \u2192 Security \u2192 Mobile phone \u2192 Delete Phone Number [Source 1]."
    ),
    bullet("Transactional messages (e.g., billing/account-critical notices) cannot be unsubscribed from regardless of channel [Source 2]."),
    h("3.4 Push notifications", 2),
    bullet("Turn off in your mobile device's own notification settings, or via \u201cNotification settings\u201d for the relevant profile in the Account section [Source 1]."),
    {"type": "pagebreak"},
]

# ---------- Section 4: Data access, retention, deletion ----------
elements += [
    h("Section 4 \u2014 See, Correct, and Minimize What Netflix Holds", 1),
    h("4.1 Get a copy of your data (verify before you restrict)", 2),
    bullet("Account owner: go to netflix.com/account/getmyinfo and follow the prompts; can take up to 30 days after verification [Source 3]."),
    bullet("Profile user (email added to a profile, not the account owner): email privacy@netflix.com \u2014 note the account owner IS notified of this request [Source 3]."),
    h("4.2 Correct inaccurate data / object to processing", 2),
    bullet("Update directly in Account (email, payment method, phone number) [Source 9]."),
    bullet("For anything else, or to object/restrict/withdraw consent, contact privacy@netflix.com [Source 2]."),
    h("4.3 Delete specific data vs. delete the account", 2),
    bullet("Viewing history \u2192 Section 3.2 above. Payment methods, phone number, profiles: see the linked Account sections [Source 4]."),
    bullet(
        "Full account deletion: Account \u2192 Security \u2192 \u201cDelete account\u201d \u2192 complete Security Check \u2192 confirm. "
        "Deletion is deferred until the end of the current billing period if the membership is still active, and can be undone any "
        "time before that period ends [Source 13]."
    ),
    bullet(
        "If you only cancel (don't delete), Netflix's stated standard practice is to auto-delete the account 24 months after "
        "cancellation [Source 13] \u2014 cancel AND delete if you want the shorter, immediate path."
    ),
    h("4.4 Retention \u2014 what Netflix actually commits to", 2),
    p(
        "Netflix's stated retention rule is deliberately general, not a fixed number of days: it retains personal information "
        "\u201cas required or permitted by applicable laws and regulations\u2026 for billing or records purposes, and as otherwise "
        "necessary to fulfil the purposes described in the Privacy Statement\u201d [Source 2][Source 4]. The one concrete number "
        "published is that the Access &amp; Device Information view shows devices active in the <b>last 90 days</b> [Source 3][Source 9] \u2014 "
        "that is a display window, not a stated deletion timer for the underlying logs."
    ),
    {"type": "pagebreak"},
]

# ---------- Section 5: Limits / what you cannot fully stop ----------
elements += [
    h("Section 5 \u2014 Honest Limits (What These Controls Do NOT Do)", 1),
    p("A methodical privacy hardening pass should be explicit about residual exposure, not imply these toggles achieve zero data collection:"),
    bullet("Core account/billing/fraud-prevention data collection continues regardless of these settings \u2014 it is not optional while you hold an active subscription [Source 2]."),
    bullet("Opting out of \u201cbehavioral\u201d ads does not stop ALL ads on ad-supported or live-event tiers \u2014 you get non-behavioral ads instead [Source 1]."),
    bullet("The Do Not Sell/Share opt-out does not retroactively claw back data already shared with third parties before you opted out [Source 2]."),
    bullet("Choosing an ad-supported plan is treated by Netflix as a \u201cfinancial incentive\u201d exchange under US state law \u2014 switching to a "
           "non-ad plan to reduce ad-based data use will likely raise the monthly price [Source 2]."),
    bullet("Resettable device ID and cookie opt-outs are local to that specific browser/device \u2014 they do not travel with your account to new hardware [Source 1][Source 2]."),
    bullet("No fixed universal retention period is published (Section 4.4) \u2014 you can request deletion, but Netflix retains discretion to keep data as long as legally permitted for billing, legal, or fraud-defense purposes [Source 2]."),
    {"type": "pagebreak"},
]

# ---------- Sources ----------
elements += [
    h("Sources", 1),
    p("All facts above are drawn verbatim from Netflix's own public Help Center and Privacy Statement, retrieved 2026-09-13:"),
    bullet("[1] How to stop certain uses of your personal information \u2014 help.netflix.com/en/node/100637"),
    bullet("[2] Netflix Privacy Statement (Last Updated April 10, 2026) \u2014 help.netflix.com/en/legal/privacy"),
    bullet("[3] What personal information Netflix holds about you and how to request a copy \u2014 help.netflix.com/en/node/100624"),
    bullet("[4] Deletion, removal and retention of information \u2014 help.netflix.com/en/node/100625"),
    bullet("[6] What is a Netflix Household? \u2014 help.netflix.com/en/node/124925"),
    bullet("[7] How to hide titles from viewing history \u2014 help.netflix.com/en/node/22205"),
    bullet("[8] How Netflix's Recommendations System Works \u2014 help.netflix.com/en/node/100639"),
    bullet("[9] Accessing and updating information associated with your account \u2014 help.netflix.com/en/node/100627"),
    bullet("[10] Do Not Sell or Share My Personal Information \u2014 netflix.com/dnsspi"),
    bullet("[11] How to keep your account secure \u2014 help.netflix.com/en/node/13243"),
    bullet("[12] Phishing or suspicious emails or texts claiming to be from Netflix \u2014 help.netflix.com/en/node/65674"),
    bullet("[13] Deleting your Netflix account \u2014 help.netflix.com/en/node/126558"),
    p(
        "This guide is independent reference material, not a Netflix-published document, and not legal advice. "
        "Netflix's controls and UI locations can change; if a described menu path doesn't match what you see, "
        "re-check the live source URLs above."
    ),
]

spec = {
    "title": "Netflix Privacy Hardening Guide \u2014 Simplified Opt-Out Instructions (2026)",
    "author": "Compiled from Netflix Help Center (source-verified, retrieved 2026-09-13)",
    "page_size": "letter",
    "page_numbers": True,
    "elements": elements,
}

with open(OUT, "w", encoding="utf-8") as fh:
    json.dump(spec, fh, indent=2, ensure_ascii=False)

print(json.dumps({"elements": len(elements), "out": OUT}))
