# Unauthenticated remote event-loop DoS against WALLET clients via oversized respond_additions / respond_removals / respond_header_blocks / respond_to_coin_updates / respond_children / respond_ses_hashes

**Target:** `https://github.com/Chia-Network/chia-blockchain`
**Commit:** `1f0a121e63a2fffc2054f8afac74fdd354468cb6` (master)
**Component:** `chia/wallet/wallet_node_api.py`
**Weakness:** CWE-770 (Allocation of Resources Without Limits or Throttling) — same root cause class as the program's already-triaged `#3550584` finding, applied to the opposite message direction.

## Summary

`#3550584` (Triaged) and its acknowledged duplicates (`#3909344`, `#3909348`, `#3909370`) establish that any `FullNodeAPI` handler whose `@metadata.request` decorator omits `list_limits` lets `Streamable.from_bytes()` synchronously deserialize an attacker-chosen, effectively unbounded list on the node's single asyncio event loop *before* the handler body ever runs — freezing all node activity for the duration of the parse.

**`chia/wallet/wallet_node_api.py` has the identical defect, in the opposite direction.** None of its handlers declare `list_limits`, and several of the corresponding `wallet_protocol` message classes carry unbounded, attacker-shaped lists:

| Handler (all bare `@metadata.request()`) | Message class | Unbounded field(s) |
|---|---|---|
| `respond_additions` (line 93) | `RespondAdditions` | `coins: list[tuple[bytes32, list[Coin]]]` (nested) |
| `respond_removals` (line 37) | `RespondRemovals` | `coins: list[tuple[bytes32, Coin \| None]]` |
| `respond_header_blocks` (line 177) | `RespondHeaderBlocks` | `header_blocks: list[HeaderBlock]` |
| `respond_to_coin_updates` (line 204) | `RespondToCoinUpdates` | `coin_states: list[CoinState]` |
| `respond_children` (line 208) | `RespondChildren` | `coin_states: list[CoinState]` |
| `respond_ses_hashes` (line 212) | `RespondSESInfo` | `reward_chain_hash: list[bytes32]`, `heights: list[list[uint32]]` |

Every handler body is a no-op `pass` — the cost is paid entirely in the dispatch-time parse, exactly as documented for the already-triaged handlers.

**This is not the same instance already triaged.** The triaged lineage covers *client → full-node* requests (a wallet or wallet-like peer attacking a full node). This report covers *full-node → wallet* responses: **any full-node peer a wallet client is connected to — which the wallet does not meaningfully authenticate, since Chia's peer CA ships with the software (as already noted in the closed `#3909370` writeup) — can freeze the wallet's own event loop** with a single oversized message. This directly matches the program's own stated top-level concern: *"issues surrounding wallet access and related security concerns."* Reference full nodes (public/community nodes, introducer-supplied peers, or a MITM on the wallet's connection) are exactly the untrusted-by-design peers this would come from.

## Why this predates the `list_limits` mechanism, and was never carried over

`list_limits` was retrofitted only onto four `FullNodeAPI` handlers: `register_for_ph_updates`, `register_for_coin_updates`, `request_puzzle_state`, `request_coin_state`. Every handler in `wallet_node_api.py` — which was never updated — still has `list_limits=None` on every registration:

```
$ grep -c list_limits chia/wallet/wallet_node_api.py
0
$ grep -c list_limits chia/full_node/full_node_api.py
4
```

Confirmed against a pip-installed `chia-blockchain==2.6.0`: at that version, `ApiRequest` doesn't even have a `list_limits` field yet — the mitigation didn't exist. The parsing mechanism this PoC exercises (`Streamable.from_bytes()` run synchronously in the dispatch wrapper, ahead of the handler body) is unchanged between that version and the pinned commit, and the *absence* of `list_limits` on every wallet-side handler at the pinned commit was confirmed directly against the source (table above, plus the grep counts).

## Vulnerability Details

Per `chia/server/api_protocol.py`, the `@metadata.request` wrapper always does:

```python
if issubclass(message_class, Streamable):
    arg = message_class.from_bytes(original, list_limits=resolved_limits)
...
return f(self, arg, *args, **kwargs)   # handler body runs only after this
```

`resolved_limits` is `None` whenever the decorator doesn't pass `list_limits=`. For all six handlers above, that's every time — the full attacker-supplied list is materialized before the (empty) handler body executes, synchronously, with no `await`, on the event loop that also drives the wallet's own sync/UI-facing logic.

Per `chia/server/ws_connection.py`, an inbound message does **not** need to correlate to a request the wallet actually sent: `_route_incoming_message` only special-cases messages whose `id` matches something in `self.pending_requests`; anything else — including an entirely unsolicited `respond_additions` — is queued and dispatched through `_api_call` → the same parsing wrapper above. No correlation check gates the parse.

## Steps to Reproduce

Attached: `poc_wallet_respond_additions.py`

Requires Python 3.11+ and `pip install chia-blockchain` (self-contained; no manual chia-blockchain checkout needed). It:

1. Builds a real `wallet_protocol.RespondAdditions` / `RespondRemovals` object with 1,450,000 outer entries (inner lists left empty to maximize entry count per byte, mirroring the reference PoCs' approach), serializes it via the real `bytes(msg)` `Streamable` encoder, and confirms the wire size stays under the 50 MiB (52,428,800-byte) websocket hard cap (`chia/server/server.py: max_message_size = 50 * 1024 * 1024`).
2. Runs an idle-loop heartbeat baseline (10 ms ticks) exactly like the reference PoCs.
3. Calls the real, unmodified `RespondAdditions.from_bytes()` / `RespondRemovals.from_bytes()` — the same call the dispatch wrapper makes — with the heartbeat still running, and measures the resulting stall.

```
$ python poc_wallet_respond_additions.py 1450000
PoC -- wallet_node_api.py: missing list_limits on respond_additions/respond_removals
chia-blockchain package: .../chia/__init__.py

[build] serializing RespondAdditions with 1,450,000 outer entries...
[build] wire size: 52.20 MB (built in 9.18s)
[build] RSS after build: 596.0 MB

=== RespondAdditions.from_bytes() -- no list_limits ===
  idle heartbeat gap   : median 10.215 ms, max 10.404 ms
  from_bytes() parse   : 4697.3 ms
  max heartbeat gap during dispatch: 4707.6 ms
  stall ratio vs idle median: 461x

[build] serializing RespondRemovals with 1,450,000 outer entries...
[build] wire size: 47.85 MB (built in 5.50s)

=== RespondRemovals.from_bytes() -- no list_limits ===
  idle heartbeat gap   : median 10.273 ms, max 10.405 ms
  from_bytes() parse   : 3325.2 ms
  max heartbeat gap during dispatch: 3330.7 ms
  stall ratio vs idle median: 324x
```

A single 52.2 MB message (well within the per-message rate-limit allowance for `respond_additions`, which permits 500–50,000 such messages per 60s window depending on negotiated rate-limit version, per `chia/server/rate_limit_numbers.py`) freezes the wallet's event loop for 4.7 seconds; `respond_removals` at the same scale freezes it for 3.3 seconds. Both exceed the ~1.7–1.8s stalls reported for the already-triaged full-node-side handlers at the same 50MB-class payload.

## Impact

Any full-node peer a wallet client is connected to — chosen by the user, supplied by an introducer, or a network-position attacker presenting a certificate signed by Chia's shared, software-embedded peer CA — can send a single ~50MB message to freeze that wallet's message-processing loop for several seconds per message, repeatably at the message type's permitted rate. Because the wallet initiates the connection but does not gate which message types its peer may then send unsolicited, this requires no interaction beyond the wallet already being connected to sync — which is the wallet's normal, expected operating state. This is a direct hit on end-user wallet availability, matching the program's explicit concern for "wallet access and related security concerns," and is distinct from the already-triaged client→full-node direction: different file, different peer role, different victim (the end user's own wallet process rather than a node operator's infrastructure).

## Suggested Fix

Declare `list_limits` on all six handlers in `chia/wallet/wallet_node_api.py`, matching the pattern already used for the four `FullNodeAPI` handlers, e.g.:

```python
@metadata.request(list_limits=lambda self: {"coins": MAX_COINS_PER_RESPONSE})
async def respond_additions(self, response: wallet_protocol.RespondAdditions) -> None:
    ...
```

with an appropriate bound for each field (matching, or tighter than, the corresponding `request_*` message's own intended cap — e.g. `respond_additions`/`respond_removals` should not need to exceed the `MAX_COIN_HASHES_PER_REQUEST`-scale bound already used to *ask* for this data). More generally: any handler accepting a `Streamable` with an unbounded `list[...]` field needs a `list_limits` declaration as a matter of course on both sides of a request/response pair, not just the request side — this class of gap appears to have been introduced precisely because the mitigation was applied per-handler rather than per-message-class.

## Supporting Material

- `poc_wallet_respond_additions.py` — self-contained PoC (installs nothing beyond `chia-blockchain` from PyPI; run directly)
