# TON Bug Bounty Self-Check Report

## Short Assessment

Status: partially correct.
Confidence: 80.
Fit bug bounty confidence: 72.
Component: `tonlib/tonlib/TonlibClient.cpp:1693` — `GetShardBlockProof::got_from_block()`.
Class: tonlib.
Self-check report: `poc/tonlib_liteserver_self_check.md`.

The vulnerability is technically confirmed in both local tree and upstream master
(`8e6f09172dc95ba3d302cc52ccc3fa9169ef0760`). `CHECK(from_.is_masterchain_ext())` on a
network-supplied `BlockIdExt` is present and unfixed. The finding gains additional credibility from
a nearby correct fix in the same class: `got_shard_block_proof()` at line 1707 uses
`if (!mc_id_.is_masterchain_ext()) abort(...)` — showing the developer is aware of the guard
pattern but omitted it in `got_from_block`. Three report completeness gaps are present (missing
commit hash, missing environment section, missing actual crash output). Eligibility confidence is
moderate: the bug bounty rules are silent on malicious-lite-server attacks, and reviewers may
treat it as "attacker must control trusted infrastructure."

---

## Repository State

- Analysis date UTC: 2026-06-01
- Input: `poc/tonlib_liteserver_check_report.md`
- Bug bounty rules repository: https://github.com/ton-blockchain/bug-bounty
- Bug bounty rules commit: `52db73b98ffd3173ecdbb21da770f15540e413c0`
- Repositories analyzed:
  - https://github.com/ton-blockchain/ton, branch `master`, commit `8e6f09172dc95ba3d302cc52ccc3fa9169ef0760`, submodules not updated
  - Local working tree: `claude/eloquent-wright-PCu1r`, based on `200a6e6` — vulnerability present at line 1693
- Local modification warnings: none relevant to this file; overlay/ and tonlib/ upstream sources unmodified
- Fetch/build limitations: project not built; static analysis only

---

## Scope Validation

- Target component: TonLib (`tonlib/tonlib/TonlibClient.cpp`)
- In scope: yes — TonLib is explicitly in scope
- Eligible category: uncertain — depends on how reviewers classify "malicious lite-server" attacks.
  The bug bounty rules exclude issues requiring the attacker to "already control the local host"
  but do not explicitly exclude malicious lite-server scenarios. Ruling is uncertain.
- Redirect required: none
- Relevant exclusions or warnings:
  - The attack requires operating a lite-server that clients connect to (appear in the global
    config) or performing a network MITM. Reviewers may classify this as "operator-controlled
    configuration" rather than a pure remote DoS.
  - Impact is confined to TonLib-based applications, not validators or full nodes.

---

## Technical Finding Summary

`GetShardBlockProof::got_from_block()` receives a `BlockIdExt` from the lite-server via
`with_last_block()` (which queries `liteServer_getMasterchainInfo`) and immediately calls
`CHECK(from_.is_masterchain_ext())` with no prior error-return guard. A lite-server returning a
non-masterchain block ID (workchain ≥ 0) as the "last known masterchain block" causes the `CHECK`
to fire → `std::abort()` → TonLib process terminates.

The inconsistency with the rest of the same class strengthens the finding: `got_shard_block_proof()`
at line 1707 correctly handles the analogous case with a graceful `if (!mc_id_.is_masterchain_ext())
abort(td::Status::Error(...))`, but `got_from_block()` uses a fatal `CHECK` on network-supplied data.

---

## Vulnerability Existence

- Exact files/functions: `tonlib/tonlib/TonlibClient.cpp` — `GetShardBlockProof::got_from_block()`, line 1693
- Verified code path (confirmed in local tree and upstream `8e6f091`):
  ```
  blocks_getShardBlockProof request
    → TonlibClient::do_request(blocks_getShardBlockProof)
      → GetShardBlockProof::start_up()                     :1677
        → client_.with_last_block(...)                     :1681  ← network query
          → got_from_block(R.move_as_ok().last_block_id)   :1685  ← network-supplied
            → CHECK(from_.is_masterchain_ext())            :1693  ← FATAL
  ```
- Triggering condition:
  - User-supplied `from` is not a masterchain block (or is zero-value default) → `start_up()`
    falls into the `with_last_block` path at line 1681
  - Lite-server responds to `liteServer_getMasterchainInfo` with `last.workchain ≥ 0`
  - `CHECK` fires → `std::abort()`
- Attacker-controlled input path: lite-server returns a shard block ID in `liteServer.masterchainInfo.last`;
  the TL schema `liteServer.masterchainInfo last:tonNode.blockIdExt ...` does not constrain the
  `workchain` field, so any integer value is TL-valid
- Supporting evidence — same class uses correct pattern at line 1707:
  ```cpp
  if (!mc_id_.is_masterchain_ext()) {
      abort(td::Status::Error("got invalid masterchain block id"));
      return;
  }
  ```
  The `CHECK` at line 1693 is a coding inconsistency, not an intentional invariant.
- Assumptions:
  - VERIFIED: `CHECK(from_.is_masterchain_ext())` at line 1693 present in local tree and upstream `8e6f091`
  - VERIFIED: the only guard before `got_from_block` is the `is_masterchain_ext()` check at
    `start_up()` line 1678 — that check covers only the user-supplied `from_`, not the
    network-returned value
  - VERIFIED: `got_shard_block_proof()` at line 1707 uses graceful error return — confirms
    developer is aware of the pattern
  - ASSUMPTION: a lite-server can return a non-masterchain `last_block_id` in a well-formed TL
    response — TL schema does not constrain workchain field
- Already fixed: **NO** — confirmed present in upstream master `8e6f09172dc95ba3d302cc52ccc3fa9169ef0760`

---

## Reproducibility

- Reproduced: not attempted (live-target testing forbidden)
- Reproduction method: static code analysis
- Reproduction confidence: 72
- Missing reproduction evidence:
  - No crash log from a local TonLib instance with a mock lite-server
  - No local `validator-engine` + modified `lite-client` execution output
  - Setting up a mock lite-server that returns `workchain=0` in `liteServer_getMasterchainInfo`
    response would provide definitive confirmation at low cost
- Live-target testing avoided: yes

---

## Bug Bounty Eligibility

- Technical validity: valid — confirmed in current upstream source; coding inconsistency is clear
- Bounty eligibility: uncertain — the attack requires a malicious or compromised lite-server.
  Legitimate lite-servers in the global config are trusted by design. The bug bounty rules are
  silent on whether malicious-infrastructure attacks on TonLib are in scope. The issue is a
  defense-in-depth / robustness improvement: `CHECK` should be a graceful error return, but the
  realistic attack surface is narrow.
- Realistic attacker prerequisites:
  - Must operate a lite-server listed in the target's configuration, OR
  - Must perform a network MITM between TonLib and a legitimate lite-server
  - Both are non-trivial; AC:H is appropriate
- Security impact: TonLib process crash; all pending operations lost; service must be restarted
- Eligibility strengthening argument:
  - The TON global config is a publicly distributed JSON file; any operator can add a lite-server
    entry to it. A malicious lite-server can appear legitimate before exploitation. The defense
    against it should be graceful error handling, not trusting network data.
- Low-priority notes:
  - Impact confined to TonLib applications, not validators or full nodes
  - The coding inconsistency within the same class (CHECK vs graceful abort at line 1707) makes
    this look like an oversight rather than an intentional design choice

---

## Severity and Claim Validation

- Claimed impact/severity: Medium, CVSS 5.3 (AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H)
- Validated impact: Medium is appropriate; CVSS components are accurate
- Overclaiming or downgrade notes:
  - UI:R is debatable — the user (application developer) must call `blocks_getShardBlockProof`
    without a pre-validated masterchain `from` block; this is an application-level API decision,
    not an end-user click. UI:N could be argued. The report's choice of UI:R is conservative and
    not overclaiming.
  - AC:H is appropriate — requires lite-server control or MITM
  - No overclaiming detected

---

## Report Completeness Check

- Title: present
- Summary: present
- Affected component: present (`tonlib/tonlib/TonlibClient.cpp:1693`)
- Affected commit: **missing** — "Affected Versions" section says "all TonLib releases as of the
  audit date" without a commit hash; should reference `8e6f09172dc95ba3d302cc52ccc3fa9169ef0760`
- Affected files/functions: present
- Attack prerequisites: present (malicious lite-server)
- Trigger conditions: present
- Reproduction steps: present (lite-server returning workchain=0 in masterchainInfo)
- Expected result: present
- Actual result: **missing** — no crash log or execution output from a mock lite-server test
- Proof of concept or evidence: present (code-level analysis with TL schema explanation and call
  chain; supporting evidence from line 1707 comparison not in original report but strengthens it)
- Security impact: present
- Suggested remediation: present (two options with code patches)
- Environment details: **missing** — OS, compiler version, TON version not specified

---

## Common Error Scan

- No RCE claimed; impact correctly bounded to process crash
- No fund theft or consensus impact claimed
- Attack complexity correctly rated High
- `CHECK` on network-supplied data is a real coding error regardless of exploitability confidence
- No hallucinated functions — `GetShardBlockProof`, `got_from_block`, `with_last_block` all
  confirmed present in source at cited line numbers
- No hallucinated call path — the `start_up` → `with_last_block` → `got_from_block` →
  `CHECK` chain is fully traceable in the source
- Eligible category uncertainty should be flagged in the submission cover note
- Additional finding not in original report: line 1707 uses the correct pattern in the same
  class — noting this in the submission strengthens the case that line 1693 is an oversight

---

## Final Verdict

Final verdict: PASS WITH WARNINGS

Detailed reasoning:
The technical finding is confirmed in upstream master. The `CHECK` on a network-supplied
`BlockIdExt` is a real coding error — the same class correctly uses `if (!mc_id_.is_masterchain_ext())
abort(...)` at line 1707, making the `CHECK` at line 1693 an obvious inconsistency rather than an
intentional invariant. The vulnerability exists, the code path is fully traceable, and the finding
is not fixed upstream.

Three completeness gaps should be resolved before submission: (1) add the affected commit hash
(`8e6f09172dc95ba3d302cc52ccc3fa9169ef0760`), (2) add an environment section, (3) note the
absence of a live crash log (static analysis only). None are blocking to the technical merit.

The primary risk is eligibility: reviewers may classify the malicious-lite-server threat model as
outside the remote-DoS bar. The submission should include a cover note explaining why this is
still in scope: the global config is public, lite-server entries can be added by any operator, and
the correct fix is straightforward. The comparison to line 1707 (correct pattern, same class)
should also be added to the report as it makes the "oversight" framing compelling.

Submission guidance: add commit hash, add environment section, add line-1707 comparison to the
report body, include eligibility cover note, then send with medium confidence.

Note: This self-check is not an official TON triage decision and does not guarantee a bounty.
Invalid or low-quality reports may reduce reviewer trust and review priority.
