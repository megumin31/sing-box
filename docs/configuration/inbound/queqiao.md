---
icon: material/new-box
---

# Queqiao reliable inbound

This preview implements the native reliable TLS/TCP and QUIC-stream
gateway. Bounded Linux amd64 native two-endpoint checks passed for TLS/TCP,
QUIC, active carrier handoff and isolated DATA handoff. This remains a preview;
it does not implement enrollment, certificate issuance, FEC or QUIC
DATAGRAM transport.

```json
{
  "type": "queqiao",
  "tag": "queqiao-in",
  "listen": "127.0.0.1",
  "listen_port": 16443,
  "credentials_path": "/path/to/private-gateway-credentials.json",
  "transport": "auto",
  "users": [
    {
      "name": "test-device",
      "account_id": "0123456789abcdef0123456789abcdef",
      "device_id": "abcdef0123456789abcdef0123456789",
      "public_key": "<raw URL-safe base64 Ed25519 public key>"
    }
  ],
  "max_sessions": 16,
  "quic_idle_timeout": "30s"
}
```

The gateway credential file has version `1`, `provider_id`, `gateway_id`,
`root_pin`, `root_certificate_pem`, `gateway_certificate_pem` and
`gateway_private_key_pem` fields. The provider ID derives from the root public
key; the root pin is its SHA-256 certificate digest in raw URL-safe base64.
The gateway certificate chain must include the provider root and identify
`queqiao://<provider_id>/gateway/<gateway_id>`. This file contains a private key;
on Unix it must be a regular, non-symlink file accessible only to its owner and
no larger than 1 MiB. Do not place its contents in logs or shared artifacts.

`users` explicitly authorizes 1–256 distinct account/device pairs, including each
device's pinned Ed25519 key. IDs are 32 lowercase hexadecimal characters. TLS
requires the provider's client certificate chain, the device URI identity,
TLS 1.3 and `queqiao/1` ALPN. Routing session/flow IDs and UDP tokens cannot grant
authorization to another principal or key. There is no insecure TLS option.

`transport` defaults to `auto`, which binds TCP and UDP on the same explicit,
nonzero port and requires `with_quic`. `tcp` works without that build tag;
`quic` binds only UDP. Existing [Listen Fields](/configuration/shared/listen/)
control the bind address. `quic_idle_timeout` defaults to 30 seconds and accepts
5 seconds through 1 minute. QUIC datagrams and incoming unidirectional streams
are disabled.

`max_sessions` defaults to 16 and accepts 1–64 active logical TCP flows or UDP
relays. Physical admission concurrency is bounded at 32, QUIC connections at 8,
and each TCP flow at two physical lanes. Replay retains at most 1 MiB and receive
queues at most 4 MiB. TCP replacement grace is 40 seconds and UDP replacement grace
is 20 seconds. Completed TCP flows retain only completion metadata for the
recovery grace. Native router EOF waits for final protocol confirmation for at
most the existing 40-second recovery budget; shutdown interrupts that wait.

Controlled kr2-to-de tests used the complete sing-box program on both endpoints,
three concurrent TCP flows, request half-close, exact payload digests, single-send
UDP probes up to 65,497 bytes, and UDP source endpoint retention. Both ordinary
and isolated DATA carrier-loss tests passed explicit frontend TCP reset cancellation
without reviving the canceled flow. Destination TCP and UDP resources were reclaimed.
This finite test does not qualify production stability or every network/platform.

The test gateway used `quic_idle_timeout: "20s"`. From reverse QUIC loss injection
to four replacement upstream TCP connections the final checks measured 21.060 and
21.029 seconds. These are connection-observation intervals, not measured application
data interruption or completed TLS/JOIN migration latency. Changing the supported
idle timeout can change silent-loss detection; lower values were not benchmarked.
The 40-second TCP and 20-second UDP recovery budgets start after loss recognition.

## Native two-endpoint acceptance (2026-10-02)

The complete Linux amd64 sing-box program ran as kr2 outbound and de native
inbound. Ordinary and isolated DATA modes each passed a 900-second fault window;
total remote case times were 950.402 and 951.982 seconds, including bootstrap,
final EOF, 45-second quiescence and client exit. Controller resource/log checks
follow separately. These are finite low-load checks, not production stability.

Each window kept three long TCP flows (8,192-byte chunks, at most one chunk per
second per flow), completed 23 short flows and 16 frontend reset cancellations,
and verified 17 single-send UDP probes at 1,200/8,192 bytes. The proxy added
5–25ms delay each direction and dropped every 47th forward / 53rd reverse QUIC
packet. At 60 seconds it blackholed QUIC for 40 seconds; at 300 and 600 seconds
it reset all four owned replacement TCP pairs. Each destination remained the
same logical socket. Exact TCP digests, EOF, one destination accept, UDP single
delivery and source-port retention passed. After quiescence both client and
gateway had 9 FDs; owned UDP relay sockets were gone. FD/RSS bounds over this
finite run do not prove absence of every leak.

Current-source Linux race tests passed with `with_quic` (504 test/subtest PASS
events, 40.635s) and without (446, 13.590s), with no DATA RACE report. The builds
took 63.504/22.271s using Go 1.27.1 and existing GCC in owned temporary storage.
Official companion and opt-in long/resource suites were skipped (8/3 SKIP events).
These skips are not covered by the package race result. The complete-program
native windows are separate non-race runtime coverage.

The first long-window attempt failed at startup after 22.729s, before injected
faults, with initial QUIC OPEN deadlines. Its cause remains unexplained; later
clean starts did not reproduce it. A subsequent 367.510s run exposed fixture
reset behavior: cross-thread socket close retained a blocked Linux recv until
its 65s timeout. An instrumented negative control failed after 168.318s; waking
only the read side before SO_LINGER-zero close preserved an immediate peer RST.
An intermediate 239.756s UDP failure exposed another fixture-only idle timeout
that consumed an unintended resume attempt. Idle reads now keep polling. App
TCP 65s / UDP probe 12s and product recovery budgets were not increased. The
corrected 240s control and both 900s windows passed; all failures are retained.

Each accepted window logged 16 gateway ERROR-level abort/grace-reclamation
entries and had 16 explicit cancellations. All have unique cancellation-time
matches: ordinary entries follow the 40s grace; isolated entries mix immediate
abort and grace. Normal-flow destination digests and EOF passed. Logs do not
carry fixture logical tags, so this is timing/count correlation, not exact
per-wire attribution. No unexplained normal-flow error was identified and no
unexpected QUIC-listener termination was logged.

Online FEC/coded DATAGRAM remains uncompleted and was not retried. Asymmetric TCP
blackhole guarantees, high load, TUN/system routing and sustained production use
are not qualified. Enrollment/renewal, proactive scoring/cooldown and reverse
carrier migration are not implemented. The earlier 21.060/21.029s figures measure
QUIC loss to four upstream TCP connects, not TLS/JOIN completion or application
recovery latency. A 20s gateway idle setting was used in these native tests;
supported values are 5s–1m, default 30s. TCP recovery is 40s and UDP 20s after
recognition, each admission 5s, at most three lifetime attempts.

See [the two-endpoint examples](../../../examples/queqiao-native/README.md) for a
Mac/Linux SOCKS client, native server and version-1 credential/profile templates.
