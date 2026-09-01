# wallet_node_api.py event-loop DoS — reproduction notes

This directory documents a fresh finding against `Chia-Network/chia-blockchain`
(commit `1f0a121e63a2fffc2054f8afac74fdd354468cb6`): the same missing-`list_limits`
event-loop-starvation bug already Triaged for the full-node's *client-facing*
handlers (`#3550584` and its acknowledged duplicates) also exists, unpatched,
on the *wallet's* response-facing handlers in `chia/wallet/wallet_node_api.py` —
meaning a malicious or MITM'd full-node peer can freeze a connected wallet
client, not just the other way around.

See `HACKERONE-REPORT.md` for the full writeup.

## Running the PoC

```bash
python3 -m venv venv
source venv/bin/activate
pip install chia-blockchain
python poc_wallet_respond_additions.py 1450000
```

No local chia-blockchain checkout, no network node, no testnet connection
required — this measures the real `Streamable.from_bytes()` parse cost
directly, exactly as the dispatch wrapper in `chia/server/api_protocol.py`
would invoke it, using the actual installed package's message classes.

Expected output (numbers will vary slightly by machine):

```
=== RespondAdditions.from_bytes() -- no list_limits ===
  idle heartbeat gap   : median ~10 ms
  from_bytes() parse   : ~4.7 s
  max heartbeat gap during dispatch: ~4.7 s
  stall ratio vs idle median: ~460x

=== RespondRemovals.from_bytes() -- no list_limits ===
  from_bytes() parse   : ~3.3 s
  stall ratio vs idle median: ~320x
```

Pass a smaller argument (e.g. `50000`) for a faster, smaller-scale run — the
script still confirms the stall pattern well below the 50MB message cap.

## Why this is a fresh finding, not a duplicate

The three reports pasted into this engagement (`#3909370`, `#3909344`,
`#3909348`) are all closed as duplicates of `#3550584`, and all three cover
**client → full-node** request handlers on `FullNodeAPI`
(`request_ses_hashes`, `request_remove_puzzle_subscriptions` /
`request_remove_coin_subscriptions`, `request_additions`). This finding is
the **full-node → wallet response** direction, in a different file
(`chia/wallet/wallet_node_api.py`), with a different attacker (any full-node
peer, not a wallet-role client) and a different victim (the wallet client's
own process, not a full node operator's). It was found by systematically
enumerating every `@metadata.request`-decorated handler across all of
chia-blockchain's API surfaces (`full_node_api.py`, `wallet_node_api.py`,
`farmer_api.py`, `harvester_api.py`, `timelord_api.py`, `crawler_api.py`,
`introducer_api.py`) and cross-checking each against its message class's
field list for unbounded `list[...]` fields with no corresponding
`list_limits` declaration.

## Also noted, not separately written up

`chia/seeder/crawler_api.py` (the DNS-seeder/crawler service, which runs
as `node_type=NodeType.FULL_NODE` with its own advertised, publicly
listening port) explicitly registers `request_additions`, `request_removals`,
`request_puzzle_solution`, and `request_header_blocks` as no-op `pass`
handlers — meaning the exact same client→server missing-`list_limits` defect
also stalls the public seeder/crawler process itself. This is very likely to
be triaged as the same root cause as `#3550584` (same message classes, same
missing declaration) rather than a fresh issue, so it isn't written up as a
separate report — but it's worth knowing the defect isn't confined to
`FullNodeAPI`.
