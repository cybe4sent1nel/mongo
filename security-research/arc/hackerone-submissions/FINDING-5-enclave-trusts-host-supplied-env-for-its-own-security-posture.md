# Arc Remote Signer's Nitro Enclave entrypoint bootstraps its own `APP_ENV` (and therefore whether it bridges its logs and telemetry back out to the host) from an unauthenticated value the host supplies over VSOCK, defaulting to the more permissive posture when the host provides nothing — inverting the project's own stated trust direction

## Assets

- **`circlefin/arc-remote-signer`** — the sole in-scope asset for this finding.
  - `docker/run_enclave.sh` — the actual production Nitro Enclave entrypoint (confirmed distinct from the dev-only `run_enclave.dev.sh`, and the one `docker/Dockerfile.enclave` sets as `ENTRYPOINT`).
  - `docker/Dockerfile.enclave` — confirms `run_enclave.sh` is the real image entrypoint and that `socat`/`iproute2` are the only extra packages installed specifically to support this bridging.

## Summary

This report is a second follow-up to FINDING-1, examining the actual Nitro Enclave boot sequence rather than the Go application code directly (FINDING-4 already covers the Go-level `EnclaveService` gRPC API). `docker/run_enclave.sh` — the real, non-dev entrypoint baked into the enclave image (`ENTRYPOINT ["/usr/local/circle/run_enclave.sh"]` in `Dockerfile.enclave`) — has the enclave ask the host, over an unauthenticated VSOCK channel, what its own operating posture should be, and defaults to the *more* permissive, telemetry-forwarding posture whenever the host doesn't answer or doesn't say exactly `prod`:

```bash
ENV_DATA=$(socat VSOCK-CONNECT:3:8000 -)
IFS='|' read -r APP_ENV DD_SERVICE DD_ENV DD_ENTITY_ID _ <<< "$ENV_DATA"

# Default APP_ENV to 'stg' if not provided by the host. This is a safe default
# as it enables non-production features like tracing.
export APP_ENV="${APP_ENV:-stg}"
...
if [ "$APP_ENV" != "prod" ]; then
    export OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4317
    socat TCP-LISTEN:4317,fork,reuseaddr VSOCK-CONNECT:3:4317 &   # OTLP traces -> host
    socat TCP-LISTEN:8126,fork,reuseaddr VSOCK-CONNECT:3:8126 &   # Datadog APM traces -> host
    socat TCP-LISTEN:8125,fork,reuseaddr VSOCK-CONNECT:3:8125 &   # DogStatsD metrics -> host
    ( cat <"$LOG_FIFO" | tee >(socat - VSOCK-CONNECT:3:8001) ) &   # enclave's own stdout/stderr -> host
    LOG_PID=$!
else
    # Make sure we drain the fifo if not sending to vsock
    cat >/dev/null < "$LOG_FIFO" &
    LOG_PID=$!
fi
```

Two problems compound here:

1. **The enclave's own security-relevant self-classification is bootstrapped from an unauthenticated value the host controls.** `ENV_DATA` arrives over a plain `socat VSOCK-CONNECT:3:8000 -` read, with no signature, no attestation binding, and no validation of its contents at all — it is simply pipe-delimited and assigned to shell variables. CID `3` is the well-known "parent instance" CID for a Nitro Enclave, i.e. the host — the exact party this architecture's own README states should not be trusted with key material ("even the host system cannot access private key material").
2. **The default, fail-safe behavior is the *more* permissive one.** If the host sends nothing, sends a malformed string, or simply never connects successfully, `APP_ENV` defaults to `stg` — which is *not* `prod` — which triggers the branch that bridges the enclave's own stdout/stderr log stream and three telemetry ports (OTLP, Datadog APM, DogStatsD) out to the host over VSOCK. The comment in the script even states the intent plainly: *"This is a safe default as it enables non-production features like tracing"* — treating "more visibility for the host" as the safe default, when for this specific architecture the safe default should be the opposite: the host is the adversary, and the fewer channels it can pull data out of the enclave through, the better, especially by default.

To be precise about what I am and am not claiming: I confirmed the enclave's own Go-level gRPC logging interceptor (`internal/common/grpc/server/interceptor/logging.go`, shared by both `internal/app` and `internal/enclave`) logs only method name, client IP, status code, and latency — never request/response payloads — and I found no other logging call anywhere in `internal/enclave/service/enclave/enclave.go` (the `SignMessage`/`GetPublicKey`/`GenerateKey`/`GetAttestation` handlers contain zero log statements). **So this specific channel does not, today, exfiltrate private key material or message content, and I am not claiming otherwise.** What it does do is: (a) invert this architecture's own stated trust direction by letting the untrusted host decide whether the enclave opens data channels back out to it, (b) default to opening them, and (c) create standing infrastructure (three bridged TCP-to-VSOCK listeners plus a log-forwarding pipe) whose only gate against carrying something sensitive in the future is that nobody has added a slightly-too-verbose debug log or trace-span attribute inside the enclave binary yet — a single easy mistake (e.g. a future `logging.Entries{"request": req}` added during debugging, or a trace span attribute that happens to include a request field) turns this already-open, host-controlled channel into an active leak, silently, because the "is this safe to enable" decision was made once, in shell, based on an unverified value from the party the architecture exists to distrust.

## Severity

Requested severity: **High** (not Critical/Extreme like FINDING-1/FINDING-4, since no concrete data exposure was demonstrated here — this is a trust-boundary/defense-in-depth architectural defect, not a proven key-leak path).
Suggested CVSS v3.1: `6.5` (`AV:A/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N`) reflecting an adjacent-network(same-host-hypervisor)-positioned attacker (the host, per this project's own threat model) gaining a low-but-nonzero confidentiality impact today, with materially higher realistic impact contingent on future logging/tracing changes this report also flags as a risk multiplier.

Rationale:
1. The trust direction is backwards for this architecture specifically: the host is the explicitly named adversary, yet it single-handedly and unilaterally controls whether the enclave opens outbound-to-host data channels, with no attestation or verification of the value it supplies.
2. The default (fail-open) behavior is the permissive one, not the restrictive one — a design choice that works against every other defense-in-depth control in this codebase, and is inconsistent with how carefully the *cryptographic* trust boundary (PCR-pinned KMS attestation, per `Dockerfile.enclave`'s own "WARNING: Changing any of these pins will produce a different enclave image, invalidating the PCR hashes" comment) is otherwise handled in this same project.
3. Confirmed no direct secret exposure today, which is why this is not filed at the same severity as FINDING-1/FINDING-4 — but the blast radius the moment any future enclave-side code adds a moderately verbose log or trace attribute is the same class of impact as those findings, and nothing in the current design would catch that regression before it silently starts leaking to the host.

## Affected Versions

- **`circlefin/arc-remote-signer`**, branch `main`, commit `a9e9fdb48c1e96a6c3fb875aba3d341e6a8af1a6` (same commit as FINDING-1/FINDING-4).

## Root Cause

`docker/run_enclave.sh` (complete file, annotated):
```bash
#!/usr/bin/env bash
set -eux
...
# Assign IP addresses to local loopback
ip addr add 127.0.0.1/32 dev lo
ip link set dev lo up

ENV_DATA=$(socat VSOCK-CONNECT:3:8000 -)                          # unauthenticated read from the host
IFS='|' read -r APP_ENV DD_SERVICE DD_ENV DD_ENTITY_ID _ <<< "$ENV_DATA"

export APP_ENV="${APP_ENV:-stg}"                                   # fails open to non-prod

[ -n "$DD_ENV" ] && export DD_ENV
[ -n "$DD_ENTITY_ID" ] && export DD_ENTITY_ID
[ -n "$DD_SERVICE" ] && export DD_SERVICE="${DD_SERVICE}-enclave"

LOG_FIFO=/tmp/log.fifo
mkfifo "$LOG_FIFO"

if [ "$APP_ENV" != "prod" ]; then
    export OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4317
    socat TCP-LISTEN:4317,fork,reuseaddr VSOCK-CONNECT:3:4317 &
    socat TCP-LISTEN:8126,fork,reuseaddr VSOCK-CONNECT:3:8126 &
    socat TCP-LISTEN:8125,fork,reuseaddr VSOCK-CONNECT:3:8125 &
    ( cat <"$LOG_FIFO" | tee >(socat - VSOCK-CONNECT:3:8001) ) &
    LOG_PID=$!
else
    cat >/dev/null < "$LOG_FIFO" &
    LOG_PID=$!
fi

APP_PUBLIC_SERVER_PORT=10350 /usr/local/circle/app \
    --enclave-config /usr/local/circle/configs/enclave.yaml run-enclave \
    2>&1 > "$LOG_FIFO" &
APP_PID=$!
...
wait "$APP_PID"
```
`docker/Dockerfile.enclave` confirms this is the genuine production entrypoint (not a dev-only artifact):
```dockerfile
ENTRYPOINT ["/usr/local/circle/run_enclave.sh"]
```
and that the only packages this image installs beyond the base runtime are exactly what this bridging needs:
```dockerfile
apt-get install -y --no-install-recommends \
    socat iproute2
```

No cryptographic verification of `ENV_DATA` is possible or attempted here — VSOCK CID `3` (the enclave's parent) is reachable only by the co-located host instance, which is a correct assumption for *isolation from the network*, but this specific value is never checked against anything the enclave itself can independently verify (e.g., it is not part of the signed attestation document, nor cross-checked against any expected value derived from the enclave's own measurements).

## Steps to Reproduce

This finding was identified by direct static reading of the actual production entrypoint script and Dockerfile, not by execution (running this specific script requires an actual AWS Nitro Enclave environment on the host side of the VSOCK channel, unavailable in this sandboxed environment). The logic is simple enough to state as a direct proof rather than requiring a live reproduction:

1. Boot the enclave image via `docker/Dockerfile.enclave`'s `ENTRYPOINT` inside a real Nitro Enclave.
2. On the host side, either don't run the process that normally connects to `VSOCK-LISTEN:8000` inside the enclave and sends the `APP_ENV|DD_SERVICE|DD_ENV|DD_ENTITY_ID` string, or connect and send a string that doesn't contain exactly `prod` as the first field (e.g. send nothing, send garbage, or simply delay/fail the connection so `socat VSOCK-CONNECT:3:8000 -` returns empty output).
3. Observe: `APP_ENV` resolves to `stg` (the `${APP_ENV:-stg}` fallback), and the enclave proceeds to bridge OTLP (4317), Datadog APM (8126), DogStatsD (8125), and its own combined stdout/stderr log stream out to the host over VSOCK — all from a single, one-line, easily reproduced host-side action (or inaction).

## Possible Solution

1. **Never let the host's self-reported environment be the sole gate for whether the enclave opens outbound telemetry/log channels back to it.** If a "which environment am I in" signal is genuinely needed pre-attestation, derive it from something the enclave can verify independently (e.g., bake the intended environment into the enclave image itself at build time, so it is covered by the same PCR measurement/attestation policy already relied on for KMS access, rather than accepting it at runtime from the untrusted host).
2. **Default closed, not open.** If the host-supplied value is missing, malformed, or ambiguous, the enclave should default to the *most* restrictive posture (no telemetry/log bridging) rather than the most permissive one. The current comment's own reasoning ("safe default... enables tracing") has the direction of "safe" backwards for this specific system's threat model.
3. **Keep a hard content ceiling on anything that does cross this channel**, independent of fixing 1/2: an explicit allowlist or redaction pass on what the enclave's logger is permitted to emit, enforced in code (not just by developer discipline), so a future added log line cannot silently start forwarding sensitive content to the host even if the channel itself remains open in non-prod builds.

## Impact

Today: the untrusted host — explicitly named as the threat this enclave architecture exists to defend against — unilaterally controls, via an unauthenticated one-shot value, whether the enclave exposes four additional outbound data channels (three telemetry ports plus its combined log stream) back to that same host, and the fail-safe default is to expose them. No concrete secret exposure was demonstrated through this specific channel as currently implemented, and I am not claiming otherwise. The risk is architectural: this is a trust-direction inversion and a standing piece of infrastructure whose only protection against carrying sensitive data in the future is the absence, so far, of a sufficiently verbose log statement or trace attribute inside the enclave binary — a single ordinary debugging change away from becoming a real leak, with no independent control in this design that would catch or prevent that regression.

## Note on AI usage

This finding was identified and written up with AI assistance, as a second follow-up to FINDING-1/FINDING-4, working against the same `circlefin/arc-remote-signer` `main` branch commit `a9e9fdb48c1e96a6c3fb875aba3d341e6a8af1a6`. The `docker/run_enclave.sh` and `docker/Dockerfile.enclave` excerpts above are transcribed directly and completely from the actual files at those paths — the reproduction section describes the script's own documented logic rather than an executed reproduction, since this requires real Nitro Enclave hardware unavailable in this sandboxed environment. Before writing this up, I re-checked `internal/common/grpc/server/interceptor/logging.go` and every handler in `internal/enclave/service/enclave/enclave.go` specifically to confirm no request/response payload or key material is logged today, so the impact section here does not overstate what is currently exposed through this channel — that check, and the resulting severity calibration (High rather than Critical), was a deliberate choice to avoid claiming a data leak that the current code does not actually produce. A human should independently verify this against a real Nitro Enclave boot sequence (observing actual `ENV_DATA` traffic on the host side of the VSOCK channel) before formal submission.
