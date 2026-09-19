# monerod: ZMQ `get_blocks_fast` RPC method has no restricted-mode size cap on `block_ids` — unbounded, blockchain-lock-held linear scan reachable over `--restricted-zmq-rpc`

## Assets

- Repository: `monero-project/monero`
- Commit audited: `9e3a31032ee2cf3cb65c908e107a9952d03bbc4f` (current `master`)
- Component: ZMQ JSON-RPC server (`src/rpc/zmq_server.cpp`, `src/rpc/daemon_handler.cpp`, `src/rpc/zmq_restricted_methods.cpp`), backed by `Blockchain::find_blockchain_supplement` (`src/cryptonote_core/blockchain.cpp`)

## Summary

The ZMQ JSON-RPC method `get_blocks_fast` (`COMMAND_RPC_GET_BLOCKS_FAST`'s ZMQ counterpart) accepts a client-supplied list of block hashes, `block_ids`, with no size limit anywhere in its handler — and, unlike every other array-typed ZMQ RPC parameter in the same file, it is not gated on `--restricted-zmq-rpc` at all. Each element of `block_ids` forces a real LMDB lookup, and the entire scan runs while holding `m_blockchain_lock` — the same recursive mutex that block acceptance and P2P block relay also need. A remote, unauthenticated ZMQ client can send an arbitrarily long list of non-existent hashes (only the final entry needs to be the real, public genesis hash) and force the daemon to walk the whole list, one lookup at a time, with that lock held for the entire duration.

This is not a transport detail of an existing report — it is the ZMQ JSON-RPC method's own independent code path, gated by its own independent restricted-mode mechanism (`zmq_restricted_methods.cpp`), which simply never enumerates this method as blocked or size-limited, unlike its sibling handlers in the very same file.

## Root Cause

**1. `get_blocks_fast` is registered in the ZMQ method table with no accompanying restriction**
(`src/rpc/daemon_handler.cpp:97`):

```cpp
{u8"get_blocks_fast", handle_message<GetBlocksFast>},
```

**2. The handler performs zero validation on `block_ids` before use** (`src/rpc/daemon_handler.cpp:141-150`):

```cpp
void DaemonHandler::handle(const GetBlocksFast::Request& req, GetBlocksFast::Response& res)
{
  std::vector<std::pair<std::pair<blobdata, crypto::hash>, std::vector<std::tuple<crypto::hash, crypto::hash, blobdata> > > > blocks;

  if(!m_core.find_blockchain_supplement(req.start_height, req.block_ids, blocks, res.current_height, res.top_block_hash, res.start_height, req.prune, true, false, COMMAND_RPC_GET_BLOCKS_FAST_MAX_BLOCK_COUNT, COMMAND_RPC_GET_BLOCKS_FAST_MAX_TX_COUNT))
  {
    res.status = Message::STATUS_FAILED;
    res.error_details = "core::find_blockchain_supplement() returned false";
    return;
  }
  ...
```

There is no `m_restricted` reference anywhere in this function. Every other array-typed request in the same class has one:

```cpp
// src/rpc/daemon_handler.cpp:250   GetTransactions::Request        — if (m_restricted && req.tx_hashes.size() > restricted_max_txs)
// src/rpc/daemon_handler.cpp:321   KeyImagesSpent::Request          — if (m_restricted && req.key_images.size() > restricted_max_key_images)
// src/rpc/daemon_handler.cpp:701   GetBlockHeadersByHeight::Request — if (m_restricted && req.heights.size() > restricted_max_block_headers)
// src/rpc/daemon_handler.cpp:867   GetOutputKeys::Request           — if (m_restricted && req.outputs.size() > restricted_max_fake_outs)
// src/rpc/daemon_handler.cpp:919   GetOutputDistribution::Request   — if (m_restricted && req.amounts != std::vector<uint64_t>(1, 0))
```

`GetBlocksFast::Request` (`src/rpc/daemon_messages.h:88-94`) has exactly the shape that would need the same treatment:

```cpp
BEGIN_RPC_MESSAGE_CLASS(GetBlocksFast);
  BEGIN_RPC_MESSAGE_REQUEST;
    RPC_MESSAGE_MEMBER(std::list<crypto::hash>, block_ids);
    RPC_MESSAGE_MEMBER(uint64_t, start_height);
    RPC_MESSAGE_MEMBER(bool, prune);
  END_RPC_MESSAGE_REQUEST;
```

**3. ZMQ's own restricted-mode blocklist does not cover this method either** (`src/rpc/zmq_restricted_methods.cpp:40-50`):

```cpp
const std::array<boost::string_ref, 9> blocked_in_restricted_mode{{
  "flush_txpool",
  "get_peer_list",
  "mining_status",
  "relay_tx",
  "save_bc",
  "set_log_categories",
  "set_log_level",
  "start_mining",
  "stop_mining"
}};
```

`get_blocks_fast` is not in this list, and this is the *only* other restricted-mode enforcement point on the ZMQ dispatch path (`src/rpc/daemon_handler.cpp:987-1022`, `DaemonHandler::handle(std::string&& request)`):

```cpp
epee::byte_slice DaemonHandler::handle(std::string&& request)
{
  ...
  const std::string request_type = req_full.getRequestType();
  if (m_restricted && is_blocked_in_restricted_mode(request_type))
  {
    Message fail;
    fail.status = Message::STATUS_FAILED;
    fail.error_details = "\"" + request_type + "\" is not available in restricted mode.";
    return FullMessage::getResponse(fail, req_full.getID());
  }

  const auto matched_handler = std::lower_bound(std::begin(handlers), std::end(handlers), request_type);
  if (matched_handler == std::end(handlers) || matched_handler->method_name != request_type)
    return BAD_REQUEST(request_type, req_full.getID());

  epee::byte_slice response = matched_handler->call(*this, req_full.getID(), req_full.getMessage());
  ...
```

So a `get_blocks_fast` request is neither blocked outright nor size-checked — it passes straight through to the handler in point 2, under `--restricted-zmq-rpc` exactly as it would without it.

**4. The victim function scans unbounded, under the blockchain lock, for the ordinary client-sync case**
(`src/cryptonote_core/blockchain.cpp:2762-2806`, the 11-argument `find_blockchain_supplement` overload that the ZMQ handler calls directly):

```cpp
bool Blockchain::find_blockchain_supplement(const uint64_t req_start_block, const std::list<crypto::hash>& qblock_ids, ...) const
{
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  ...
  if(req_start_block > 0)
  {
    ...
  }
  else
  {
    // find_blockchain_supplement's start_height is the highest block idx included in qblock_ids that's *also* in the main chain
    if(!find_blockchain_supplement(qblock_ids, start_height))
    {
      return false;
    }
    ...
```

When `req.start_height == 0` (the default, and the normal case for a client syncing from scratch — exactly what an unauthenticated ZMQ caller controls), this calls into the two-argument overload that does the actual unbounded scan (`src/cryptonote_core/blockchain.cpp:2421-2461`):

```cpp
bool Blockchain::find_blockchain_supplement(const std::list<crypto::hash>& qblock_ids, uint64_t& starter_offset) const
{
  CRITICAL_REGION_LOCAL(m_blockchain_lock);   // held for the ENTIRE scan below

  if(qblock_ids.empty()) { ... return false; }

  auto gen_hash = m_db->get_block_hash_from_height(0);
  if(qblock_ids.back() != gen_hash)            // only requires the LAST entry = genesis
  {
    ...
    return false;
  }

  auto bl_it = qblock_ids.begin();
  uint64_t split_height = 0;
  for(; bl_it != qblock_ids.end(); bl_it++)    // O(N), no bound on N anywhere
  {
    try
    {
      if (m_db->block_exists(*bl_it, &split_height))
        break;
    }
    catch (const std::exception& e) { ... return false; }
  }
  ...
```

`m_blockchain_lock` is a recursive mutex, which is why the outer overload can safely hold it while calling into the inner one — but it provides no protection against a second thread. Any concurrent ZMQ request, HTTP RPC call, or P2P block-processing path that also needs `m_blockchain_lock` blocks for the full duration of this scan.

**5. Config wiring — `--restricted-zmq-rpc` is a real, independent, documented daemon flag**
(`src/daemon/daemon.cpp:135-146`):

```cpp
if (!command_line::get_arg(vm, daemon_args::arg_zmq_rpc_disabled))
{
  verify_zmq_rpc_bind(vm);
  const bool restricted = command_line::get_arg(vm, daemon_args::arg_restricted_zmq_rpc);
  zmq.reset(new zmq_internals{core, p2p, restricted});
  ...
```

`restricted` here flows straight into `DaemonHandler`'s constructor as `m_restricted` (`src/rpc/daemon_handler.cpp:123-124`, `DaemonHandler::DaemonHandler(cryptonote::core& c, t_p2p& p2p, bool restricted) : m_core(c), m_p2p(p2p), m_restricted(restricted)`), confirming `--restricted-zmq-rpc` genuinely is the operator's intended hardening knob for exactly this class of parameter — it is simply never consulted for this one method.

## Reachability

- ZMQ RPC is enabled by default (`--no-zmq` disables it explicitly; it is not disabled by default).
- `--restricted-zmq-rpc` is the documented flag operators use to run a public-facing ZMQ RPC endpoint safely, mirroring `--restricted-rpc` for HTTP.
- Under `--restricted-zmq-rpc`, `get_blocks_fast` is reachable to any client who can open a ZMQ REQ/REP connection to the configured `--zmq-rpc-bind-port`, with no authentication of any kind.
- Every other array-typed ZMQ method with equivalent per-element daemon work is capped under this same flag; this one alone is not.

## Steps to Reproduce (not executed live; static call-chain trace against ZMQ source)

Precondition: `monerod` running with ZMQ RPC enabled (default) and `--restricted-zmq-rpc` set, as an operator would for a public node.

```python
# Pseudocode: a ZMQ REQ client sending a get_blocks_fast request with a large,
# entirely attacker-chosen block_ids list (random hashes, real genesis hash last).
import zmq, json

ctx = zmq.Context()
sock = ctx.socket(zmq.REQ)
sock.connect("tcp://TARGET_HOST:ZMQ_RPC_PORT")

block_ids = [random_32_byte_hex() for _ in range(N)]
block_ids.append(GENESIS_HASH_HEX)   # required: qblock_ids.back() must equal genesis

request = {
    "method": "get_blocks_fast",
    "params": {"block_ids": block_ids, "start_height": 0, "prune": False},
}
sock.send_string(json.dumps(request))
print(sock.recv_string())
```

Each such request forces the daemon to walk the full `N`-length list, one `block_exists()` LMDB lookup at a time, with `m_blockchain_lock` held for the entire scan — before it can even determine there's no common ancestor (or find the genesis fallback) and return. There is no restricted-mode check anywhere on this call path to reject or truncate an oversized `block_ids` list.

## Severity

**High.** This is a network-reachable (`AV:N`), unauthenticated (`PR:N`), no-user-interaction (`UI:N`) resource-consumption issue against a lock shared with core blockchain operations (block acceptance, P2P relay), not merely a single RPC worker thread — a stronger primitive than a plain per-thread DoS. It affects any daemon run with `--restricted-zmq-rpc`, which is precisely the configuration operators use to expose ZMQ RPC publicly.

## Possible Solutions

1. Add a `m_restricted && req.block_ids.size() > <some sane cap>` check to `DaemonHandler::handle(const GetBlocksFast::Request&, ...)` (`src/rpc/daemon_handler.cpp:141`), mirroring the pattern already used for `GetTransactions`, `KeyImagesSpent`, `GetBlockHeadersByHeight`, `GetOutputKeys`, and `GetOutputDistribution` in the same file.
2. Alternatively (or additionally), enforce the same cap inside `Blockchain::find_blockchain_supplement` itself (`src/cryptonote_core/blockchain.cpp:2421`), so the protection is transport-agnostic and cannot be missed by any current or future RPC surface that calls into it.
3. Consider whether `get_blocks_fast` belongs in ZMQ's `blocked_in_restricted_mode` list (`src/rpc/zmq_restricted_methods.cpp:40`) if there is no legitimate reason for a restricted/public ZMQ client to call it at all.

## Note on AI usage

This finding was produced through static source review of the actual ZMQ RPC code in this repository at the commit above, by an AI assistant (Claude), guided by a human researcher. All cited file paths, line numbers, and code excerpts were verified directly by reading the cited files in full on this checkout. No live daemon was stood up and no ZMQ request was actually sent to trigger and time the described scan; the reproduction steps are a call-chain trace through the real code, not the output of an executed exploit. The severity/impact assessment (specifically, the magnitude of lock-hold time and its effect on concurrent RPC/P2P callers) should be verified empirically against a synced node before being treated as fully confirmed — the structural claim (no size cap, no restricted-mode gate, lock held for the full scan) is verified directly from source and does not depend on chain size or content.
