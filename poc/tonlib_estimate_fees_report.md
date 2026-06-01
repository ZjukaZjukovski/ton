# TonLib – Process Crash via Unknown OutAction Tag in `query_estimateFees`

**Severity:** Medium  
**Component:** `tonlib/tonlib/TonlibClient.cpp:1020` — `calc_fwd_fees()`  
**Impact:** A contract producing an unknown OutAction tag crashes any TonLib process calling `query_estimateFees` against it  
**CVSS 3.1:** 5.9 (AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H)  
**Scope (bug-bounty):** C++ core / TonLib ✓

---

## Summary

`calc_fwd_fees()` processes the output action list from smart contract execution during fee
estimation. It iterates the action list in reverse and calls `block::gen::t_OutAction.get_tag(cs)`
to dispatch on the action type. If the action tag does not match any known `OutAction` constructor
(`action_send_msg`, `action_set_code`, `action_reserve_currency`, `action_change_library`),
`get_tag()` returns `-1` and the subsequent `CHECK(tag >= 0)` terminates the process via
`std::abort()`.

Any contract that writes a raw cell with an unrecognized opcode to the C5 (output actions) register
can trigger this crash against any TonLib consumer of `query_estimateFees`.

---

## Vulnerability Details

### Vulnerable Code

```cpp
// tonlib/tonlib/TonlibClient.cpp:1016–1020
for (int i = n - 1; i >= 0; --i) {
    vm::CellSlice cs = load_cell_slice(actions[i]);
    CHECK(cs.fetch_ref().not_null());        // removes the prev-list ref (invariant, safe)
    int tag = block::gen::t_OutAction.get_tag(cs);
    CHECK(tag >= 0);                         // ← SIGABRT if tag is unknown
    switch (tag) { ... }
}
```

`get_tag()` reads bits from the cell slice to match one of the four known constructors:

| Constructor | Tag (hex) |
|-------------|-----------|
| `action_send_msg` | `0x0ec3c86d` |
| `action_set_code` | `0xad4de08e` |
| `action_reserve_currency` | `0x36e6b809` |
| `action_change_library` | `0x26fa1dd4` |

Any other 32-bit prefix in the action cell causes `get_tag()` to return `-1`.

### Root Cause

The TLB grammar for `OutAction` (`crypto/block/block.tlb:403–411`) has exactly four constructors.
A TVM contract, however, can write arbitrary bytes to the C5 register — the VM itself does not
validate the action opcode before storing it. Action list validation by `calc_fwd_fees()` is the
first point of TLB interpretation, and it uses `CHECK` instead of a graceful error return.

The `switch` statement at line 1021 handles only the four known tags:
```cpp
switch (tag) {
    case block::gen::OutAction::action_set_code:
        return td::Status::Error("estimate_fee: action_set_code unsupported");
    case block::gen::OutAction::action_send_msg: { ... }
    case block::gen::OutAction::action_reserve_currency: { ... }
    case block::gen::OutAction::action_change_library: { ... }
}
// No default case — unreachable only because CHECK above crashes first
```

If a future action type is added to TVM without updating the `CHECK`/`switch` in `calc_fwd_fees`,
every fee estimation call against contracts using the new action type will crash TonLib.

### Call Chain

```
tonlib_api::query_estimateFees request (RPC/API call)
  → TonlibClient::do_request(query_estimateFees)       TonlibClient.cpp:4554
    → TonlibClient::query_estimate_fees(id, ...)        TonlibClient.cpp:4540
      → SmcQuery::estimate_fees(ignore_chksig, state)   TonlibClient.cpp:1069
        → TVM execution of contract (local simulation)
          → calc_fwd_fees(res.actions, ...)             TonlibClient.cpp:1110
            → CHECK(tag >= 0)                           :1020  ← CRASH
```

### TVM Action Register Behavior

TVM's `SETCODE`/`RAWRESERVE`/`SENDRAWMSG`/`SETLIBCODE` instructions each write a specific
constructor prefix. A contract using the `PUSHCONT` + raw cell builder instructions can write
any 32-bit prefix into C5 as the action tag without TVM validation:

```fift
; Malicious action cell: unknown 4-byte tag 0xDEADBEEF
<b 16r DEADBEEF 32 u, b> PUSHCONT
SETCONTVAL   ; or equivalent raw cell push to C5
```

The exact mechanism depends on TVM opcode availability, but the C5 register accepts arbitrary
cells — TON's design defers action validation to the block collation step, not to the VM itself.

---

## Reproduction Steps

1. Deploy a TON smart contract that writes a cell with an unrecognized 32-bit tag as an output
   action. The simplest approach is a contract that uses raw builder opcodes to push a cell with
   tag `0x00000000` (or any value not in the four known tags) to C5.

2. Obtain the contract address and construct a TonLib query object pointing to it.

3. Call `query_estimateFees` against the deployed contract:
   ```json
   { "@type": "query.estimateFees",
     "id": <query_id_for_malicious_contract>,
     "ignore_chksig": true }
   ```

4. Observe SIGABRT from `CHECK(tag >= 0)` in `calc_fwd_fees` at `TonlibClient.cpp:1020`.

### Why AC:H

Deploying a specific smart contract on the TON blockchain requires paying gas fees and waiting for
the contract to be confirmed. The contract must then be the target of a `query_estimateFees` call.
This is a higher complexity than a pure packet injection attack.

---

## Impact

Any TonLib service that exposes `query_estimateFees` as an external API (block explorer, wallet
backend, bot) can be crashed by directing fee estimation at a crafted contract. The crash is
deterministic and repeatable — every call to `estimateFees` against the malicious contract address
will crash the process. Recovery requires a process restart; persistent attack causes a denial of
service as long as the contract remains on-chain.

Additionally, this is a forward-compatibility hazard: if TON introduces new action opcodes in a
future hard fork, TonLib would begin crashing for all contracts using those new actions until
patched.

CVSS detail:
- **AV:N** — API is network-accessible (TonLib services)
- **AC:H** — Requires deploying a specific contract on mainnet (costs gas)
- **PR:N** — Contract deployment requires no special privilege
- **UI:N** — No user interaction; attacker controls both contract and API call
- **C:N / I:N** — No data exposure or modification
- **A:H** — Complete process crash, repeatable

---

## Suggested Fix

Replace both `CHECK` calls with graceful error returns:

```cpp
// tonlib/tonlib/TonlibClient.cpp:1016–1020
for (int i = n - 1; i >= 0; --i) {
    vm::CellSlice cs = load_cell_slice(actions[i]);
    auto prev_ref = cs.fetch_ref();
    if (prev_ref.is_null()) {
        return td::Status::Error("estimate_fee: malformed action cell (missing prev ref)");
    }
    int tag = block::gen::t_OutAction.get_tag(cs);
    if (tag < 0) {
        return td::Status::Error(PSLICE() << "estimate_fee: unknown action tag");
    }
    switch (tag) {
        ...
        default:
            return td::Status::Error(PSLICE() << "estimate_fee: unhandled action tag " << tag);
    }
}
```

The `default` case in the `switch` makes the guard forward-compatible: new action types added in
future VM versions are silently rejected with an error rather than a crash.

---

## Affected Versions

All TonLib releases as of the audit date. The `calc_fwd_fees` function has used `CHECK` for tag
validation since fee estimation support was added.

---

## Timeline

- Bug discovered during security review of TonLib RPC deserialization and fee estimation paths.
- Reported via TON bug bounty program: https://github.com/ton-blockchain/bug-bounty
