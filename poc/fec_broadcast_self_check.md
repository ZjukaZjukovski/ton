# TON Bug Bounty Self-Check Report

## Short Assessment

Status: partially correct.
Confidence: 80.
Fit bug bounty confidence: 85.
Component: `overlay/broadcast-fec.cpp` — `BroadcastFec::broadcast_checked()` / `add_part()`.
Class: `any node crashes other node`.
Self-check report: `poc/fec_broadcast_self_check.md`.

Core vulnerability is technically valid and confirmed in both local and upstream source code. The
`while (!parts_.empty())` loop and the uncapped `parts_` map are present in upstream master
(`8e6f09172dc95ba3d302cc52ccc3fa9169ef0760`). The attacker-controlled path from any network peer
to the vulnerable code is verified. Two non-blocking deficiencies prevent a `correct` rating:
the report omits the affected commit hash and environment details, and the PoC has not been
executed against a local test node (dry-run output only). No live-target testing was attempted per
self-check rules.

---

## Repository State

- Analysis date UTC: 2026-06-01
- Input: `poc/fec_broadcast_dos_report.md` + `poc/fec_broadcast_dos.py`
- Bug bounty rules repository: https://github.com/ton-blockchain/bug-bounty
- Bug bounty rules commit: `52db73b98ffd3173ecdbb21da770f15540e413c0`
- Repositories analyzed:
  - https://github.com/ton-blockchain/ton, branch `master`, commit `8e6f09172dc95ba3d302cc52ccc3fa9169ef0760`, submodules not updated (static analysis only)
  - Local working tree: `claude/eloquent-wright-PCu1r`, commit `fa984a7` (2 commits ahead of `master` baseline `200a6e6`); contains audit artifacts, not upstream modifications
- Local modification warnings: local branch contains poc/ files added during this audit session; upstream overlay/ source files are unmodified
- Fetch/build limitations: project not built; all analysis is static; submodules not initialized

---

## Scope Validation

- Target component: TON C++ core — Overlay network layer (`overlay/broadcast-fec.cpp`)
- In scope: yes — TON Blockchain Core C++ is explicitly listed in scope
- Eligible category: yes — full-node/validator DoS via network input
- Redirect required: none
- Relevant exclusions or warnings:
  - Bug bounty rules exclude "issues related to misbehaving validator ability to force other validators to do useless work" — this finding is triggered by **any** network peer (not only validators), so the exclusion does not apply
  - Bug bounty rules exclude Ton Storage and rldp-http-proxy — not relevant here
  - Catchain is noted as out-of-scope in the self-check template — this is the Overlay layer, not Catchain; not excluded

---

## Technical Finding Summary

`BroadcastFec::broadcast_checked()` at `overlay/broadcast-fec.cpp:186` contains a synchronous
`while (!parts_.empty())` loop that flushes all accumulated FEC parts to overlay neighbours in a
single actor-turn with no yield. The `parts_` map (line 174) has no size cap; `add_part()` (line
71) inserts unconditionally. Any peer that receives `BroadcastCheckResult::NeedCheck` — which is
every unauthenticated peer after `update_validators()` sets `AllowFec` without `Trusted` — can
accumulate up to 43,696 parts (~55 MB) per broadcast. If `check_broadcast` resolves successfully,
the loop fires and issues up to 218,480 `send_closure` calls inside the single-threaded
`OverlayImpl` actor, blocking it for an estimated 44–109 ms per broadcast.

Even when `check_broadcast` fails, ~55 MB of allocation persists for 60 seconds (GC TTL),
enabling memory exhaustion via ≈18 concurrent broadcasts (≈1 GB).

---

## Vulnerability Existence

- Exact files/functions:
  - `overlay/broadcast-fec.cpp:186` — `BroadcastFec::broadcast_checked()` (unbounded loop)
  - `overlay/broadcast-fec.cpp:71` — `BroadcastFec::add_part()` (no parts_ cap)
  - `overlay/broadcast-fec.cpp:174` — `parts_` member declaration
  - `overlay/overlays.h:304–305` — `unauth_broadcast_size_rate_limit_ = {}` (unlimited default)
  - `validator/full-node-shard.cpp:1347` — `update_validators()` sets `AllowFec` without `Trusted`
- Verified code path (confirmed in local tree and upstream `8e6f091`):
  - `update_validators()` sets `OverlayPrivacyRules{max_fec_broadcast_size, AllowFec, authorized_keys}` — no `Trusted` flag
  - `overlays.h:127`: `!(flags_ & Trusted)` → returns `NeedCheck` for any unknown sender
  - `broadcast-fec.cpp:308–344` (`BroadcastFecPart::run`): parts from untrusted senders are stored in `parts_` but NOT distributed until `broadcast_checked` fires
  - `overlays.h:304–305`: `unauth_broadcast_size_rate_limit_ = {}` → `RateLimiterWindow::check` returns `true` unconditionally when `duration_ == 0`
  - `broadcast-fec.cpp:192`: unbounded `while (!parts_.empty())` confirmed at both line references
- Attacker-controlled input path:
  - Any peer on the public overlay network (no authentication required after `update_validators` is called)
  - Attacker constructs FEC broadcast parts: valid `broadcast_hash`, `seqno < symbols_count*2+4`, valid signature from an ephemeral Ed25519 key
  - Sends all 43,696 parts sequentially
  - `BroadcastFecPart::run` routes each part through the untrusted accumulation path; all parts land in `parts_`
  - `check_broadcast` resolves (default callback always succeeds); `broadcast_checked` fires; loop runs
- Assumptions:
  - VERIFIED: `update_validators()` is called during normal full-node operation when the validator set becomes known — this is steady-state behaviour, not an edge case
  - VERIFIED: default `Overlays::Callback::check_broadcast` at `overlays.h:328–331` calls `promise.set_value(td::Unit())` unconditionally — loop always fires for the default callback used by shard overlays
  - NOTE: report's "check_broadcast success conditions" table implies shard overlay requires a valid `tonNode_externalMessageBroadcast`. This is overstated — `FullNodeShardImpl` does not override `check_broadcast` in its overlay callback; the default always-succeed path applies
  - VERIFIED: `RateLimiterWindow::check` with `duration_=0` returns `true` at `tdutils/td/utils/RateLimiterWindow.h`
- Already fixed: **NO** — confirmed present in upstream master `8e6f09172dc95ba3d302cc52ccc3fa9169ef0760`

---

## Reproducibility

- Reproduced: not attempted (live-target testing forbidden per self-check rules)
- Reproduction method: static code analysis + dry-run PoC output
- Reproduction confidence: 75
- Missing reproduction evidence:
  - No crash log or memory trace from an actual local node run
  - No `ton-bug-triage` or local `validator-engine` output
  - PoC `fec_broadcast_dos.py` dry-run output is included in the report; actual execution against a local test node would significantly raise confidence
- Live-target testing avoided: yes — self-check rules prohibit testing against mainnet, testnet, or public nodes; PoC was not executed

---

## Bug Bounty Eligibility

- Technical validity: valid — core code path verified in current upstream source
- Bounty eligibility: eligible — full-node availability impact via unauthenticated network input; overlay layer is in scope
- Realistic attacker prerequisites: yes — any peer with network access to the target node; no authentication, no validator privileges, no stake required
- Security impact:
  - Memory exhaustion: ~55 MB per 16 MB broadcast × 18 concurrent = ~1 GB; process OOM or OS-level kill after sustained attack
  - Actor blocking: 44–109 ms per broadcast × 10–23 concurrent = full actor saturation; all overlay operations (block propagation, peer discovery) queue indefinitely
  - Combined: full-node becomes unresponsive to the overlay network; block sync and block propagation halt; validator loses connectivity
- Low-priority notes: none — impact is concrete, attacker path is unauthenticated, code is confirmed unpatched

---

## Severity and Claim Validation

- Claimed impact/severity: High, CVSS 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
- Validated impact: High — the actor-blocking and memory exhaustion paths are both real; the quantitative analysis (memory table, CPU table) is internally consistent with the code
- Overclaiming or downgrade notes:
  - CVSS 7.5 is appropriate; no overclaiming detected
  - Minor overstatement in "check_broadcast success conditions" table: shard overlay uses the always-succeed default callback, not a callback that requires a valid external message — the attack is easier than described, not harder; does not reduce severity
  - Memory estimate of ~55 MB uses worst-case symbol overhead; practical figure is slightly lower; not materially wrong

---

## Report Completeness Check

- Title: present
- Summary: present
- Affected component: present (`overlay/broadcast-fec.cpp:192`)
- Affected commit: **missing** — no specific TON commit hash referenced; filled with upstream master `8e6f09172dc95ba3d302cc52ccc3fa9169ef0760` for this self-check
- Affected files/functions: present
- Attack prerequisites: present (unauthenticated peer after `update_validators`)
- Trigger conditions: present
- Reproduction steps: present (dry-run and full-attack CLI commands in PoC section)
- Expected result: present (dry-run expected output shown)
- Actual result: **missing** — no observed execution output from a real or local node; only dry-run expected output is provided
- Proof of concept or evidence: present (`poc/fec_broadcast_dos.py` with dry-run mode; quantitative tables)
- Security impact: present (memory + actor-blocking quantified)
- Suggested remediation: present (three fixes with code patches)
- Environment details: **missing** — OS, compiler version, TON version not specified

---

## Common Error Scan

- No RCE claimed without code execution
- No fund theft or consensus impact claimed — claim is correctly scoped to node availability (DoS)
- No modified binaries or disabled checks required — vulnerability is in production code, default configuration
- No debug-only path — `broadcast-fec.cpp` is production overlay code, not a test stub
- Not fixed in latest branch — confirmed in upstream master `8e6f091`
- No hallucinated functions — all cited functions (`broadcast_checked`, `add_part`, `distribute_part`, `BroadcastFecPart::run`) confirmed in source
- No AI-fabricated call paths — the attacker-controlled path from `OverlayPrivacyRules::check_rules` through `BroadcastFecPart::run` to `broadcast_checked` is fully traceable in code
- Minor overstatement in `check_broadcast` callback section (shard overlay uses always-succeed default, not a validator-message check) — does not invalidate the finding; makes attack prerequisites easier
- PoC not executed against live target — correct per self-check rules; dry-run output provided; note this as missing actual execution evidence in submission

---

## Final Verdict

Final verdict: PASS WITH WARNINGS

Detailed reasoning:
The vulnerability is technically confirmed in both local and upstream source code. The attacker path
from an unauthenticated network peer to the unbounded accumulation and synchronous loop is fully
traceable without fabrication. The `parts_` map cap absence, the `while (!parts_.empty())` loop,
the default always-succeed `check_broadcast` callback, and the zero-rate-limit for unauthorized FEC
are all verified. The finding is in scope, not fixed upstream, and the impact is concrete.

The two blocking completeness gaps are: (1) no affected commit hash in the report (add
`8e6f09172dc95ba3d302cc52ccc3fa9169ef0760` or the hash at submission time), and (2) no environment
details. Both are easy to add and non-blocking to the technical merit. The missing actual
reproduction output (live or local-node crash log) is noted but acceptable given the prohibitions
on live-target testing; submitting with the dry-run output and quantitative analysis is reasonable.

The minor overstatement in the `check_broadcast` success table should be corrected: the shard
overlay uses the always-succeed default callback, making the attack unconditional rather than
requiring a valid external message — this strengthens, not weakens, the finding.

Submission guidance: add affected commit hash, add environment section, correct the
`check_broadcast` callback note, then send.

Note: This self-check is not an official TON triage decision and does not guarantee a bounty.
Invalid or low-quality reports may reduce reviewer trust and review priority.
