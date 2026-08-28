"""
Live reproduction of the txn_prepared_participant_unauthorized_commit_abort.js scenario against
the real mongod/mongos 8.3.8 binaries, driven by pymongo (no mongosh available).

Mirrors the vendor's own regression test for SERVER-130544 exactly:
  1. rwuser (readWrite on testdb only, no cluster/internal privilege) starts a cross-shard
     transaction via mongos (shard0 = coordinator, shard1 = pure participant).
  2. The coordinator is frozen at hangBeforeWritingDecision -- every participant has prepared
     and voted, but no decision has been written/sent yet.
  3. rwuser opens a DIRECT connection to shard1 (the participant) and attempts
     commitTransaction / abortTransaction on that exact lsid/txnNumber, with no coordinator
     involved at all.
  4. Expect: Unauthorized (per the SERVER-130544 fix). Then release the coordinator and verify
     atomicity holds (both writes commit together, at the coordinator's single decision).
"""
import pymongo, threading, time, sys, uuid
from bson import Timestamp
from bson.binary import Binary
from bson.int64 import Int64
import pymongo.synchronous.client_session as client_session

MONGOS = 'mongodb://rwuser:rwuserPwd@127.0.0.1:27300/testdb'
SHARD0_SYSTEM = ('127.0.0.1', 27311)   # coordinator (primary shard for testdb, hosts _id<0)
SHARD1_DIRECT = 'mongodb://rwuser:rwuserPwd@127.0.0.1:27321/testdb?directConnection=true'

with open('/tmp/claude-0/-home-user-mongo/88417634-60f9-5bda-b080-646aad79e105/scratchpad/sharded_cluster/keyfile/key1') as f:
    KEYCONTENT = ''.join(f.read().split())

def system_client(host, port):
    return pymongo.MongoClient(f'mongodb://{host}:{port}/', directConnection=True,
                                username='__system', password=KEYCONTENT,
                                authSource='local', authMechanism='SCRAM-SHA-256',
                                serverSelectionTimeoutMS=10000)

def run_test(id_on_shard0, id_on_shard1, txn_number_raw, action):
    """action: 'commit' or 'abort'"""
    lsid = {'id': Binary.from_uuid(uuid.uuid4())}
    txn_number = Int64(txn_number_raw)
    result = {}

    def commit_via_mongos():
        try:
            mc = pymongo.MongoClient(MONGOS, serverSelectionTimeoutMS=30000)
            db = mc.get_database('testdb')
            db.command({
                'insert': 'coll', 'documents': [{'_id': id_on_shard0}],
                'lsid': lsid, 'txnNumber': txn_number, 'stmtId': 0,
                'startTransaction': True, 'autocommit': False,
            })
            db.command({
                'insert': 'coll', 'documents': [{'_id': id_on_shard1}],
                'lsid': lsid, 'txnNumber': txn_number, 'stmtId': 1,
                'autocommit': False,
            })
            res = mc.admin.command({
                'commitTransaction': 1, 'lsid': lsid, 'txnNumber': txn_number,
                'autocommit': False,
            })
            result['commit_via_mongos'] = res
        except Exception as e:
            result['commit_via_mongos_error'] = f'{type(e).__name__}: {e}'

    coord = system_client(*SHARD0_SYSTEM)
    fp_res = coord.admin.command({'configureFailPoint': 'hangBeforeWritingDecision', 'mode': 'alwaysOn'})
    # 'count' is CUMULATIVE since the failpoint was created / mongod started -- it is NOT reset by
    # 'mode: off' and does not restart per-test. Must wait for count+1 (a genuinely NEW hit), never
    # a fixed 'timesEntered: 1', or a stale historical hit from an earlier run/test satisfies the
    # wait instantly and the "frozen" check becomes a false positive.
    baseline_count = fp_res['count']
    result['fp_baseline_count'] = baseline_count

    t = threading.Thread(target=commit_via_mongos, daemon=True)
    t.start()

    # Wait for the coordinator to actually hit the failpoint (all participants prepared+voted),
    # using the real waitForFailPoint command (requires enableTestCommands, which is set).
    waited_ok = False
    try:
        coord.admin.command({'waitForFailPoint': 'hangBeforeWritingDecision',
                              'timesEntered': baseline_count + 1, 'maxTimeMS': 15000})
        waited_ok = True
    except Exception as e:
        result['wait_error'] = f'{type(e).__name__}: {e}'
    result['coordinator_frozen'] = waited_ok

    # DIAGNOSTIC: check actual transaction state on shard1 (as __system) during the freeze.
    # No 'active': true filter -- a prepared transaction sitting idle (no in-flight op, just
    # waiting on the coordinator's decision) would be invisible under that filter.
    # NOTE: pymongo's driver-level session machinery does not necessarily put the raw 'lsid' dict
    # we hand it on the wire verbatim (implicit-session handling can substitute its own lsid), so
    # rather than assume our own `lsid` var matches the real prepared transaction's session, we
    # read the REAL lsid straight out of shard1's own session catalog (matched by txnNumber, which
    # empirically IS preserved) and use THAT for the direct attack -- removing any ambiguity about
    # which lsid the live prepared transaction is actually keyed on.
    real_lsid = None
    try:
        shard1_sys = system_client('127.0.0.1', 27321)
        curop = shard1_sys.admin.command({'currentOp': 1, '$or': [
            {'active': True}, {'active': False, 'transaction': {'$exists': True}}
        ]})
        entries = [
            {k: o.get(k) for k in ('lsid', 'txnNumber', 'transaction', 'active', 'opid', 'type')}
            for o in curop.get('inprog', [])
        ]
        result['shard1_currentOp_full'] = entries
        for o in entries:
            txn = o.get('transaction')
            if txn and txn.get('parameters', {}).get('txnNumber') == txn_number:
                real_lsid = o['lsid']
        result['real_lsid_found_on_shard1'] = real_lsid
    except Exception as e:
        result['shard1_diag_error'] = f'{type(e).__name__}: {e}'

    # Clients only ever send {'id': <uuid>} for lsid -- 'uid' is a server-internal field derived
    # from the authenticated identity, not something a client provides on the wire.
    attack_lsid = {'id': real_lsid['id']} if real_lsid is not None else lsid

    # THE ACTUAL TEST: direct commit/abort attempt on the pure participant (shard1), as rwuser.
    # IMPORTANT: pymongo's Database.command()/admin.command() silently substitutes its OWN
    # driver-managed implicit-session lsid on the wire, discarding whatever raw 'lsid' key we put
    # in the command dict (confirmed empirically -- the lsid in the resulting error never matched
    # what we passed). To actually put our chosen attack_lsid on the wire we force an explicit
    # ClientSession's private _server_session.session_id to our target value and drive the command
    # through session=, which pymongo *does* honor for the lsid it serializes.
    try:
        direct = pymongo.MongoClient(SHARD1_DIRECT, serverSelectionTimeoutMS=10000)
        forged_session = direct.start_session()
        # start_session() hands back a lazy '_EmptyServerSession' placeholder that only becomes a
        # real _ServerSession (with a session_id we could override) on first actual use -- build a
        # real one directly instead so our forged lsid is in place before anything is sent.
        real_ss = client_session._ServerSession(0)
        real_ss.session_id = attack_lsid
        forged_session._server_session = real_ss
        if action == 'commit':
            now_ts = direct.admin.command({'hello': 1})['$clusterTime']['clusterTime']
            wrong_commit_ts = Timestamp(now_ts.time + 60, 0)
            direct_res = direct.admin.command({
                'commitTransaction': 1, 'txnNumber': txn_number,
                'autocommit': False, 'commitTimestamp': wrong_commit_ts,
                'writeConcern': {'w': 'majority'},
            }, session=forged_session)
        else:
            direct_res = direct.admin.command({
                'abortTransaction': 1, 'txnNumber': txn_number,
                'autocommit': False,
            }, session=forged_session)
        result['direct_attempt_result'] = direct_res
        result['direct_attempt_error'] = None
    except pymongo.errors.OperationFailure as e:
        result['direct_attempt_result'] = None
        result['direct_attempt_error'] = f'{e.code} {e.details.get("codeName")}: {e.details.get("errmsg")}'
    except Exception as e:
        result['direct_attempt_result'] = None
        result['direct_attempt_error'] = f'UNEXPECTED {type(e).__name__}: {e}'

    # Release the coordinator and let the legitimate commit finish.
    coord.admin.command({'configureFailPoint': 'hangBeforeWritingDecision', 'mode': 'off'})
    t.join(timeout=30)

    return result


if __name__ == '__main__':
    print("=== TEST 1: direct COMMIT attempt on frozen prepared participant ===")
    r1 = run_test(-1, 1, 4242, 'commit')
    for k, v in r1.items():
        print(f"  {k}: {v}")

    print()
    print("=== TEST 2: direct ABORT attempt on frozen prepared participant ===")
    r2 = run_test(-2, 2, 4343, 'abort')
    for k, v in r2.items():
        print(f"  {k}: {v}")

    # Final atomicity check via mongos.
    mc = pymongo.MongoClient(MONGOS, serverSelectionTimeoutMS=10000)
    docs = list(mc.testdb.coll.find({'_id': {'$in': [-1, 1, -2, 2]}}))
    print()
    print("Final documents visible via mongos:", docs)
