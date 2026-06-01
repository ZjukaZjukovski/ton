# TonLib – Process Crash via DNS Type Confusion in `finish_dns_resolve`

**Severity:** Medium  
**Component:** `tonlib/tonlib/TonlibClient.cpp:5272` — `TonlibClient::finish_dns_resolve()`  
**Impact:** Any TonLib process resolving a domain under a malicious DNS contract is crashed with SIGABRT  
**CVSS 3.1:** 5.3 (AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H)  
**Scope (bug-bounty):** C++ core / TonLib ✓

---

## Summary

`finish_dns_resolve()` calls `td::Variant::get<EntryDataNextResolver>()` unconditionally whenever
`entries[0].partially_resolved == true`, without first verifying that the stored variant type actually
is `EntryDataNextResolver`. `td::Variant::get<T>()` enforces the type match with an internal
`CHECK(offset == offset_)` call, which terminates the process via `std::abort()` on mismatch.

A malicious DNS smart contract that stores any non-`NextResolver` record type (e.g. `dns_text`) in
the next-resolver slot causes every TonLib client resolving a subdomain of that contract to crash.

---

## Vulnerability Details

### Vulnerable Code

```cpp
// tonlib/tonlib/TonlibClient.cpp:5247–5273
void TonlibClient::finish_dns_resolve(...) {
  TRY_RESULT_PROMISE(promise, entries, dns->resolve(name, category));

  if (entries.size() == 1 && entries[0].partially_resolved && ttl > 0) {
    // ... prefix validation ...

    // BUG: no type check before get<>()
    auto address = entries[0].data.data.get<ton::ManualDns::EntryDataNextResolver>().resolver;
    //                                   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    // td::Variant::get<T>() calls CHECK(offset == offset_) → SIGABRT if type != NextResolver
    return do_dns_request(prefix, category, ttl - 1, std::move(block_id), address, std::move(promise));
  }
  ...
}
```

### Root Cause

`partially_resolved` is set in `ManualDns.cpp:184` based only on `raw_entry.partially_resolved`,
which is `true` whenever `prefix_size < encoded_name.size()` (partial name match) at
`ManualDns.cpp:437–439`. The `data` field is parsed independently by
`DnsInterface::EntryData::from_cellslice()` (`ManualDns.cpp:115–154`), which returns one of five
types based on the TLB tag in the cell:

| TLB tag | Parsed type |
|---------|-------------|
| `dns_text` | `EntryDataText` |
| `dns_next_resolver` | `EntryDataNextResolver` |
| `dns_adnl_address` | `EntryDataAdnlAddress` |
| `dns_smc_address` | `EntryDataSmcAddress` |
| `dns_storage_address` | `EntryDataStorageAddress` |

Nothing in the code path enforces that `partially_resolved == true` implies the type is
`EntryDataNextResolver`. The types are completely independent.

### Crash Mechanism

`td::Variant::get<T>()` is defined in `tdutils/td/utils/Variant.h:247–249`:

```cpp
auto &get() {
    CHECK(offset == offset_);   // FATAL if stored type != requested type
    return *get_unsafe<offset>();
}
```

`CHECK` expands to `td::detail::do_check(...)` which ultimately calls `std::abort()`.

### Call Chain

```
tonlib_api::dns_resolve request (RPC/API call)
  → TonlibClient::do_request(dns_resolve)       TonlibClient.cpp:5314
    → do_dns_request(name, category, ttl, ...)   TonlibClient.cpp:5317–5328
      → ManualDns::run_get_method → smart contract execution on-chain
        → finish_dns_resolve(...)                TonlibClient.cpp:5247
          → entries[0].data.data.get<EntryDataNextResolver>()  :5272  ← CRASH
```

---

## Reproduction Steps

1. Deploy a TON DNS smart contract that implements the DNS interface, but stores a `dns_text`
   record (tag `0x7473780b`) in the slot returned when `partially_resolved=true`.  
   Concretely: when queried for `sub.example.ton`, return a partial resolution with
   `prefix_size < query_length` and `data = dns_text("hello")`.

2. Configure any TonLib client to use a standard lite-server.

3. Call the `dns_resolve` API with a name that routes through the malicious contract:
   ```json
   { "@type": "dns.resolve", "account_address": "<malicious_contract>",
     "name": "sub.example.ton", "category": 0, "ttl": 5 }
   ```

4. Observe SIGABRT / `CHECK(offset == offset_)` failure with stack trace in
   `TonlibClient::finish_dns_resolve`.

---

## Impact

Any TonLib-based application (wallets, explorers, bots) that calls `dns_resolve` on a user-supplied
or attacker-controlled domain crashes immediately. The attacker needs only to deploy one malicious
DNS contract and publish its address; all downstream resolution attempts by any client are affected.

CVSS detail:
- **AV:N** — Triggered over the TON network via lite-server
- **AC:H** — Requires deploying a specific DNS smart contract on mainnet
- **PR:N** — Deploying contracts requires no special privilege
- **UI:R** — A user must initiate a DNS resolution request toward the malicious contract
- **C:N / I:N** — No data exposure or state modification
- **A:H** — Complete process crash

---

## Suggested Fix

Add a type check before accessing the variant:

```cpp
// tonlib/tonlib/TonlibClient.cpp:5271–5273
auto& entry_data = entries[0].data.data;
if (!entry_data.is<ton::ManualDns::EntryDataNextResolver>()) {
  TRY_STATUS_PROMISE(promise,
      TonlibError::Internal("DNS partially_resolved entry has unexpected data type"));
}
auto address = entry_data.get<ton::ManualDns::EntryDataNextResolver>().resolver;
```

Alternatively, use `get_if<T>()` or `visit()` to handle all types gracefully:

```cpp
const auto* next_resolver = entry_data.get_if<ton::ManualDns::EntryDataNextResolver>();
if (!next_resolver) {
  TRY_STATUS_PROMISE(promise, TonlibError::Internal("expected dns_next_resolver entry"));
}
auto address = next_resolver->resolver;
```

---

## Affected Versions

All TonLib releases as of the audit date. The `finish_dns_resolve` function has contained this
assumption since DNS resolution support was added.

---

## Timeline

- Bug discovered during security review of TonLib RPC deserialization paths.
- Reported via TON bug bounty program: https://github.com/ton-blockchain/bug-bounty
