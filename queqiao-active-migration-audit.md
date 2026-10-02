# Native reliable Queqiao preview review

2026-10-02. Branch `work/queqiao-active-carrier-migration`, based on released
`ca23865dec450fa28421436c8bf6ec218a9cff55`. This preview adds the native authenticated
gateway and opt-in established QUIC-to-TLS/TCP migration. It does not claim the
complete Queqiao feature set or production qualification.

## Behavior and security boundary

The native inbound registers TLS/TCP and reliable QUIC streams using TLS 1.3,
`queqiao/1` ALPN, pinned Ed25519 provider/gateway URI identities and explicit
account/device plus public-key authorization. IDs and relay tokens do not grant
authentication. Profile and gateway files are owner-only bounded regular files;
no insecure TLS option, enrollment or renewal is provided.

`quic_active_fallback` defaults to false. Recognized established path loss selects
ordinary TLS/TCP for that logical flow's remaining lifetime; isolated roles retire
together. Identity/protocol refusal, application deadlines and cancellation are
terminal. TCP JOIN retains destination, offsets, replay/deduplication and FIN.
UDP resume uses a same-principal expiring token, rotates wire IDs, preserves its
relay and never replays PACKET frames. In-flight UDP can be lost.

Router EOF previously aborted a completed logical stream before final ACKs.
The fix waits only after both FINs and received final offset, within the existing
40s recovery bound and interruptible by shutdown; incomplete/error closes remain
immediate. Two focused tests passed 20 repetitions (40 PASS events).

## Prior finite matrix

Complete native Linux amd64 TLS, pure QUIC, ordinary handoff and DATA-isolated
handoff checks passed with concurrent flows, early half-close, destination-confirmed
unacknowledged bursts and explicit frontend RST. The final bounded handoff cases
took 35.392/32.944s, with exactly four replacement TCP connections. Single-send
UDP payloads up to 65,497 bytes retained their destination source endpoint; this
does not establish real 65,507-byte forwarding or lossless UDP. Earlier graceful
cancellation runs used five replacements and do not qualify explicit RST behavior.
Frozen protocol comparisons use official revision `9229f773`; no current-upstream
feature parity claim is made.

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

## Publication and cleanup scope

Only the user fork feature branch and a distinct prerelease are publication targets.
Existing releases and upstream workflow guards are preserved. The exact commit,
asset hashes, downloaded-asset verification and actual CI state are recorded in
the release verification report; lack of a CI run is not a CI pass. Darwin builds
receive compile/version checks only; native two-endpoint runtime evidence is Linux
amd64 IPv4. The TCP-only build rejects QUIC/auto configurations.

Tests used existing trusted SSH, owned temporary directories and a separately
authorized expiring identity. No production deployment, SSH/security changes,
route/firewall/sysctl/namespace edits or production-service stops were performed.
Production service and normalized read-only nft state are checked during final
cleanup. Public assets contain placeholders and sanitized evidence, no temporary
profiles, test credentials, private keys, caches or Git metadata.
