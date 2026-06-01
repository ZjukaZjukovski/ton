# TonLib – Process Crash via Malicious Lite-Server Response in `GetShardBlockProof`

**Severity:** Medium  
**Component:** `tonlib/tonlib/TonlibClient.cpp:1693` — `GetShardBlockProof::got_from_block()`  
**Impact:** A malicious or compromised lite-server can crash any connected TonLib process with one response  
**CVSS 3.1:** 5.3 (AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H)  
**Scope (bug-bounty):** C++ core / TonLib ✓

---

## Summary

`GetShardBlockProof::got_from_block()` receives a `BlockIdExt` from the lite-server via
`with_last_block()` and immediately calls `CHECK(from_.is_masterchain_ext())`. If the lite-server
returns a non-masterchain block ID as the "last known block", the `CHECK` macro terminates the
TonLib process via `std::abort()`. No other validation is performed before the crash.

---

## Vulnerability Details

### Vulnerable Code

```cpp
// tonlib/tonlib/TonlibClient.cpp:1677–1703
void start_up() override {
    if (from_.is_masterchain_ext()) {
        got_from_block(from_);
    } else {
        // Query lite-server for the last known block
        client_.with_last_block([SelfId = actor_id(this)](td::Result<LastBlockState> R) {
            if (R.is_error()) {
                td::actor::send_closure(SelfId, &GetShardBlockProof::abort, R.move_as_error());
            } else {
                td::actor::send_closure(SelfId, &GetShardBlockProof::got_from_block,
                                        R.move_as_ok().last_block_id);  // ← from network
            }
        });
    }
}

void got_from_block(ton::BlockIdExt from) {
    from_ = from;
    CHECK(from_.is_masterchain_ext());  // ← SIGABRT if lite-server returned shard block
    ...
}
```

### Root Cause

The code correctly validates `from_` when it is supplied by the caller (line 1678:
`if (from_.is_masterchain_ext()) got_from_block(from_)`) — the user-supplied block is checked
before calling `got_from_block`. However, the network-supplied `last_block_id` from `with_last_block()`
is forwarded to `got_from_block()` without the same guard. Inside `got_from_block`, the assumption
is enforced with `CHECK()` rather than a proper error return.

`with_last_block()` fetches `liteServer_getMasterchainInfo` and returns `last_block_id`. Nothing in
the TonLib client verifies that the lite-server actually returned a masterchain block ID before
passing it downstream. A lite-server that returns a shard block ID (workchain ≥ 0, or any block
with `shard != 0x8000000000000000`) will cause the CHECK to fire.

### Crash Mechanism

`CHECK(from_.is_masterchain_ext())` expands to a conditional that calls `td::detail::do_check()`
→ logs the failure → calls `std::abort()`. This terminates the entire TonLib process, not just the
current query.

### Call Chain

```
tonlib_api::blocks_getShardBlockProof request
  → TonlibClient::do_request(blocks_getShardBlockProof)    TonlibClient.cpp:6440
    → td::actor::create_actor<GetShardBlockProof>(...)
      → GetShardBlockProof::start_up()                      TonlibClient.cpp:1677
        → client_.with_last_block(...)                      (lite-server query)
          → liteServer_getMasterchainInfo response
            → got_from_block(R.move_as_ok().last_block_id)  TonlibClient.cpp:1685
              → CHECK(from_.is_masterchain_ext())            :1693  ← CRASH
```

---

## Reproduction Steps

1. Set up a modified lite-server (or intercept the TL response) that replies to
   `liteServer.getMasterchainInfo` with a `liteServer.masterchainInfo` where
   `last.workchain = 0` (base workchain) instead of `-1` (masterchain).

   The `last` field is a `tonNode.blockIdExt` TL object:
   ```
   liteServer.masterchainInfo last:tonNode.blockIdExt ...
   ```
   Setting `last.workchain = 0` and `last.shard = <any shard>` produces a non-masterchain block ID.

2. Connect TonLib to this lite-server.

3. Call `blocks_getShardBlockProof` with any shard block ID and without specifying `from`:
   ```json
   { "@type": "blocks.getShardBlockProof",
     "id": { "@type": "ton.blockIdExt", "workchain": 0, ... } }
   ```
   (When `from` is not a masterchain block, `start_up()` queries the lite-server for the last block.)

4. Observe SIGABRT from `CHECK(from_.is_masterchain_ext())` at `TonlibClient.cpp:1693`.

### Why AC:H

The attacker must either:
- Control a lite-server that TonLib clients connect to, **or**
- Perform a MITM on the UDP/TCP connection between TonLib and the lite-server.

Both require a network position advantage, hence High Attack Complexity.

---

## Impact

Any TonLib application that calls `blocks_getShardBlockProof` without a pre-validated `from` block
will crash if connected to a malicious lite-server. Public lite-servers listed in the global
configuration are an obvious attack surface; a compromised or malicious entry there affects all
clients using that server.

CVSS detail:
- **AV:N** — Triggered via lite-server network response
- **AC:H** — Requires controlling or compromising a lite-server
- **PR:N** — Public lite-servers require no special privilege to operate
- **UI:R** — A user must initiate a `blocks_getShardBlockProof` call with an unresolved `from` block
- **C:N / I:N** — No data exposure or modification
- **A:H** — Complete process crash (all pending TonLib operations lost)

---

## Suggested Fix

Replace the `CHECK` with a proper error path:

```cpp
// tonlib/tonlib/TonlibClient.cpp:1691–1693
void got_from_block(ton::BlockIdExt from) {
    from_ = from;
    if (!from_.is_masterchain_ext()) {
        abort(td::Status::Error("lite-server returned non-masterchain block as last block"));
        return;
    }
    client_.send_query(...);
}
```

Additionally, validate the lite-server response in `with_last_block()` before forwarding it:

```cpp
// in the with_last_block callback:
auto last_block_id = R.move_as_ok().last_block_id;
if (!last_block_id.is_masterchain_ext()) {
    td::actor::send_closure(SelfId, &GetShardBlockProof::abort,
        td::Status::Error("lite-server returned invalid last_block_id"));
    return;
}
td::actor::send_closure(SelfId, &GetShardBlockProof::got_from_block, last_block_id);
```

---

## Affected Versions

All TonLib releases as of the audit date. The `GetShardBlockProof` actor has used `CHECK` here
since its introduction.

---

## Timeline

- Bug discovered during security review of TonLib lite-server interaction paths.
- Reported via TON bug bounty program: https://github.com/ton-blockchain/bug-bounty
