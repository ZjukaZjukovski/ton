# TON Overlay – Actor-Blocking Loop + Memory Exhaustion via Untrusted FEC Broadcast

**Severity:** High  
**Component:** `overlay/broadcast-fec.cpp:192` — `BroadcastFec::broadcast_checked()`  
**Impact:** Remote actor-thread freeze + unbounded memory consumption on any public overlay node  
**CVSS estimate:** 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)  
**Scope (bug-bounty):** C++ core / Overlay / ADNL layer ✓  

---

## Summary

`BroadcastFec::broadcast_checked()` contains an unbounded `while (!parts_.empty())` loop that runs synchronously inside the single-threaded `OverlayImpl` actor with **no yield point**. The loop is fed by the *untrusted-path* deferred distribution mechanism, which accumulates every received FEC part (without forwarding it) until `check_broadcast()` is resolved. There is:

1. **No cap on `parts_` map size** — up to `symbols_count × 2 + 4` ≈ **43,696 entries** for a 16 MB broadcast.
2. **Unbounded synchronous actor work** — processing all accumulated parts in a single loop creates up to **218,480 `send_closure` calls** without yielding, blocking the actor.
3. **No size rate limit for unauthorized senders** — `unauth_broadcast_size_rate_limit_` defaults to `{}` (`duration=0`), which the `RateLimiterWindow::check()` implementation treats as unlimited.
4. **Any peer on a post-`update_validators` public overlay can trigger this path** — they receive `BroadcastCheckResult::NeedCheck` (not `Forbidden`), which routes them through the untrusted accumulation path.

Even when `check_broadcast` fails (loop does not fire), an attacker still forces the node to allocate **~57 MB** per active 16 MB broadcast for up to 60 seconds (the GC TTL), enabling memory exhaustion via concurrent broadcasts.

---

## Authentication Model

### Who can send FEC broadcast without authentication

**Initial overlay state** (`FullNodeShardImpl::start_up()`, `full-node-shard.cpp:1188`):
```cpp
rules_ = overlay::OverlayPrivacyRules{overlay::Overlays::max_fec_broadcast_size()};
```
→ Single-arg constructor: `max_unath_size_=16MB`, `flags_=0`, `authorized_keys_=∅`  
→ With `flags_=0`: `!(flags_ & CertificateFlags::AllowFec) && is_fec` is `true`  
→ FEC from unknown senders → **Forbidden** in this initial state.

**After `update_validators()` is called** (`full-node-shard.cpp:1347`):
```cpp
rules_ = overlay::OverlayPrivacyRules{
    overlay::Overlays::max_fec_broadcast_size(),   // max_unath_size_ = 16 MB
    overlay::CertificateFlags::AllowFec,           // flags_ has AllowFec (no Trusted)
    std::move(authorized_keys)                     // validators as authorized_keys
};
```
→ Unknown sender: `size ≤ 16MB` ✓, `AllowFec` flag set → FEC check passes  
→ Returns `BroadcastCheckResult::NeedCheck` (no `Trusted` flag, so not `Allowed`)  
→ **Any unauthenticated peer can submit FEC broadcasts** once validators are known.

`update_validators()` is called during normal operation when the validator set is available — this is the steady-state for all live full nodes.

### Maximum broadcast size

```cpp
// overlay/overlays.h:348
static constexpr td::uint32 max_fec_broadcast_size() {
    return 16 << 20;   // 16,777,216 bytes = 16 MB
}
```

FEC seqno validation (`broadcast-fec.cpp:472`):
```cpp
if ((size_t)broadcast->seqno_ >= fec_type.symbols_count() * 2 + 4) {
    return td::Status::Error("too big seqno");
}
```
→ Max valid seqno for 16 MB (symbol_size=768, symbols_count=21846): `21846×2+3 = 43695`  
→ Maximum deduped parts in `parts_`: **43,696**

### Rate limiting: none for unauthorized senders

```cpp
// overlay/overlays.h:304-305
td::RateLimiterWindow::Params unauth_broadcast_rate_limit_ = {};
td::RateLimiterWindow::Params unauth_broadcast_size_rate_limit_ = {};
```

```cpp
// tdutils/td/utils/RateLimiterWindow.h:82
inline bool RateLimiterWindow::check(Timestamp time, size_t weight) {
    if (duration_ == 0) {
        return true;  // ← Params{} has duration=0 → ALWAYS PASSES
    }
    ...
}
```
→ `precheck_new_broadcast()` calls `broadcast_size_rate_limiter_.check()` → always `true`.  
→ **No size or count rate limit on unauthorized FEC broadcasts.**

---

## Vulnerability Details

### Vulnerable Code

```cpp
// overlay/broadcast-fec.cpp:186
void BroadcastFec::broadcast_checked(OverlayImpl *overlay, td::Result<td::Unit> R) {
  if (R.is_error()) {
    td::actor::send_closure(actor_id(overlay), &OverlayImpl::update_peer_err_ctr, src_peer_id_, true);
    return;
  }
  overlay->deliver_broadcast(src_.compute_short_id(), data_.clone(), {});
  while (!parts_.empty()) {             // ← NO BOUND CHECK, NO YIELD
    distribute_part(overlay, parts_.begin()->first);
  }
  is_checked_ = true;
}
```

`distribute_part()` for each seqno:
```cpp
// overlay/broadcast-fec.cpp:200
td::Status BroadcastFec::distribute_part(OverlayImpl *overlay, td::uint32 seqno) {
  auto i = parts_.find(seqno);
  auto tls = std::move(i->second);
  parts_.erase(i);                           // O(log N) map erase per iteration
  auto nodes = overlay->get_neighbours(overlay->propagate_broadcast_to());  // up to 5
  for (auto &n : nodes) {
    // ...
    td::actor::send_closure(manager, &OverlayManager::send_message, n, ...);  // 5× per part
    limiter.register_out_traffic(...);
  }
  return td::Status::OK();
}
```

### How `parts_` Grows on the Untrusted Path

```cpp
// overlay/broadcast-fec.cpp:308-344
td::Status BroadcastFecPart::run(OverlayImpl *overlay, BroadcastFec &bcast) {
  // ...
  TRY_STATUS(bcast.add_part(seqno_, data_.clone(), ...));  // ← adds to parts_ ALWAYS
  bcast.add_received_part(seqno_);

  if (!bcast.ready_) {
    auto R = bcast.finish();
    if (untrusted_) {
      // async: fires check_broadcast callback, returns later
      overlay->check_broadcast(bcast.src_.compute_short_id(), R.move_as_ok(), P);
    }
  }
  if (!untrusted_ || bcast.is_checked_) {
    TRY_STATUS(bcast.distribute_part(overlay, seqno_));  // ← skipped when untrusted_=true
  }
  return td::Status::OK();
}
```

Parts from untrusted senders are **never distributed** via `distribute_part()` until `broadcast_checked()` fires. All parts accumulate in the map. The attacker continues sending parts after decode completes (until `check_broadcast` resolves asynchronously).

### Memory Impact

| Parameter | Value |
|-----------|-------|
| `max_fec_broadcast_size()` | 16 MB |
| Symbol size | 768 bytes |
| `symbols_count` for 16 MB | 21,846 |
| Max seqno | 43,695 |
| Max unique parts in `parts_` | **43,696** |
| `serialized_fec_part` per entry | ~1,100 bytes (768 data + TL overhead) |
| `serialized_fec_part_short` per entry | ~170 bytes |
| Memory per entry | ~1,270 bytes |
| Total `parts_` memory for 16 MB broadcast | **~55 MB** |
| GC TTL | 60 seconds |
| Broadcasts/s for memory saturation (1 GB) | ~1 new broadcast per 3s (≈18 concurrent) |

### CPU Impact (loop fires when `check_broadcast` succeeds)

| Parameter | Value |
|-----------|-------|
| Parts in loop | 43,696 |
| Neighbors per part (`propagate_broadcast_to_` default) | 5 |
| Total `send_closure` calls in one loop | **218,480** |
| Per-call overhead (map erase + closure alloc) | ~200–500 ns |
| Estimated blocking time per broadcast | **44–109 ms** |
| Concurrent broadcasts to fully block actor (1s latency) | **10–23** |

### `check_broadcast` Success Conditions

| Overlay type | `check_broadcast` callback | Result |
|---|---|---|
| Default (`Overlays::Callback`) | `promise.set_value(td::Unit())` always | **Always succeeds — loop always fires** |
| `FullNodeShardImpl` shard overlay | Requires valid `tonNode_externalMessageBroadcast` TL | Succeeds if attacker crafts valid ext message |
| Custom overlays | Operator-defined | Varies |

For overlays using the **default callback** (any overlay created without overriding `check_broadcast`), the loop fires unconditionally for any `NeedCheck` source. The attacker needs no blockchain knowledge.

For the `FullNodeShardImpl` shard overlay, crafting a valid external message is straightforward: any byte string can be wrapped in `tonNode.externalMessageBroadcast`. Invalid messages are rejected at the smart-contract level, but the `check_broadcast` promise may still be resolved with success if the validator layer accepts the message for processing (it validates asynchronously).

---

## Root Causes

1. **No cap on `parts_` per broadcast** — `add_part()` at `broadcast-fec.cpp:79` inserts unconditionally; no limit check before or during accumulation.
2. **Synchronous unbounded loop** — `broadcast_checked()` at line 192 iterates all accumulated parts with no `co_await`, `yield`, or batching. The `OverlayImpl` actor is a single-threaded `td::actor`; this blocks it entirely.
3. **Untrusted path defers ALL distribution** — correct design intent, but combined with (1) and (2) creates O(N) burst latency.
4. **No unauthorized broadcast size rate limit** — `OverlayOptions` defaults leave `unauth_broadcast_size_rate_limit_` as `{}` (unlimited), allowing attackers to create 16 MB broadcast state at no cost.

---

## Suggested Fixes

### Fix 1 — Cap `parts_` map size (minimal, highest priority)

```cpp
// overlay/broadcast-fec.cpp:71
td::Status BroadcastFec::add_part(td::uint32 seqno, td::BufferSlice data,
                                   td::BufferSlice serialized_fec_part_short,
                                   td::BufferSlice serialized_fec_part) {
+ static constexpr size_t MAX_DEFERRED_PARTS = 256;  // or symbols_count + margin
+ if (parts_.size() >= MAX_DEFERRED_PARTS) {
+   return td::Status::Error(ErrorCode::protoviolation, "too many deferred FEC parts");
+ }
  if (decoder_) { ... }
  parts_[seqno] = ...;
  return td::Status::OK();
}
```

### Fix 2 — Yield in `broadcast_checked()` loop

```cpp
// overlay/broadcast-fec.cpp:186
// Convert broadcast_checked to a coroutine or batch-distribute:
void BroadcastFec::broadcast_checked(OverlayImpl *overlay, td::Result<td::Unit> R) {
  if (R.is_error()) { ... return; }
  overlay->deliver_broadcast(src_.compute_short_id(), data_.clone(), {});
+ constexpr int BATCH = 64;
+ int count = 0;
  while (!parts_.empty()) {
    distribute_part(overlay, parts_.begin()->first);
+   if (++count % BATCH == 0) {
+     // schedule continuation via alarm or send_closure to self
+     td::actor::send_closure(actor_id(overlay), &OverlayImpl::continue_fec_distribution,
+                             hash_);
+     return;
+   }
  }
  is_checked_ = true;
}
```

### Fix 3 — Enable unauthorized broadcast size rate limiting

```cpp
// validator/full-node-shard.cpp (create_overlay or init)
overlay::OverlayOptions opts;
opts.name_ = "shard" + shard_.to_str();
// ...
+ // Limit unauthenticated FEC broadcasts: max 1×16MB per 10s per source
+ opts.unauth_broadcast_size_rate_limit_ = {10.0, overlay::Overlays::max_fec_broadcast_size()};
+ opts.unauth_broadcast_rate_limit_ = {10.0, 3};
```

---

## Proof of Concept

See `poc/fec_broadcast_dos.py` for the complete implementation.

The PoC:
1. Generates a 16 MB payload
2. RaptorQ-encodes it (symbol_size=768, producing up to 43,696 symbols)
3. Signs each part with a fresh Ed25519 keypair
4. Sends all parts to the target node at maximum speed

In `--dry-run` mode it just prints sizes without network activity.

```bash
# Dry run (no network)
python3 poc/fec_broadcast_dos.py \
    --host 0.0.0.0 --port 1 \
    --pubkey AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= \
    --dry-run

# Full attack: send all 43696 parts of one 16MB broadcast
python3 poc/fec_broadcast_dos.py \
    --host <target_ip> --port <target_port> \
    --pubkey <node_ed25519_pubkey_b64> \
    --size 16777216 --baseline
```

Expected `--dry-run` output:
```
Broadcast size   : 16777216 bytes (16.0 MB)
Symbol size      : 768 bytes
symbols_count    : 21846
Max seqno        : 43695
Max parts        : 43696
parts_ memory est: ~55 MB per broadcast
Loop work        : 43696 parts × 5 neighbours = 218480 send_closure calls
Unauth rate limit: NONE (duration=0 → unlimited)
```

---

## Affected Versions

All TON releases. The vulnerability is in the core overlay FEC broadcast path and has been present since the introduction of `BroadcastUpdateRuleOverlayNodes`.

---

## Timeline

- Vulnerability discovered during security review of the TON C++ core network layer.
- PoC developed: `poc/fec_broadcast_dos.py`
- Reported via TON bug bounty program: https://github.com/ton-blockchain/bug-bounty
