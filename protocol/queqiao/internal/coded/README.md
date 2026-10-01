# Offline Queqiao coded datagram codec

This package implements protocol-1 source/repair envelopes, GF(256) coefficient
and repair arithmetic, a fixed-window decoder, packing and fragment reassembly.
It is not imported by the Queqiao outbound, registry or CLI. It has no network
carrier, timers, background workers, loss estimator or automatic parity policy.
QUIC DATAGRAM remains disabled in the running outbound.

Encoder and Decoder are single-owner objects. Input and output are synchronous.
Parse returns a borrowed vector view; the encoder/decoder copy bytes they retain.
Returned frames do not alias retained decoder symbols. The encoder keeps the
newest 256 source vectors, and Repair takes an explicit span of 1–256.

Protocol requirements are fixed: repair spans outside 1–256 are rejected before
window admission; the decoder starts with and always retains 512 source slots.
There is no reactive window growth. Sequence, ESI and RID are separate uint32
counters. Serial comparisons handle wrapping, discard stale values, and reject
the inherently ambiguous distance of exactly 2^31. A large forward jump clears
at most one window; it never iterates over the peer's entire advertised gap.

Local admission limits are deliberately separate from protocol constants:

- DatagramBytes defaults to 1200 and accepts 26–4111. Source vectors reserve
  room for a 15-byte repair header, so their maximum is DatagramBytes minus 15
- No vector exceeds 4096 bytes, even when parsing an envelope directly
- A reconstructed opaque frame is at most 46 + 128 KiB bytes
- A group uses at most 512 fragments; all unfinished groups together retain at
  most 512 parts. Groups with inconsistent or overlapping metadata are rejected
- One Input returns at most 4096 frames, 4 MiB of frame payload, and 512 lost IDs
- WorkLimit defaults to 16 Mi charged byte operations per Input and is capped at
  64 Mi. Charged work includes vector validation/padding scans, duplicate
  comparisons, hashing, vector copies/growth, equation arithmetic/zero scans,
  and output copies. Fixed-size header/scalar and bounded metadata iteration
  are additional overhead; this is not a wall-clock or total CPU instruction cap
- The conservative retained vector/coefficient/fragment payload bound is
  3 × 512 × (DatagramBytes − 15) + 512² bytes, plus fixed metadata and Go object
  overhead. This is a retained-state bound, not a claim about process RSS or
  caller-retained output. Output, temporary buffers and the shared 64 KiB GF
  table are separate

DatagramBytes and the 512-fragment local ceiling can reject otherwise legal
protocol input under the configured resource policy. They do not redefine the
wire protocol. Very small configured datagrams may be unable to carry a maximum
frame within 512 fragments; EncodeFrame returns ErrBudget before changing any
counter or retained symbol. Future online integration must explicitly handle
these limits and reliable-stream fallback, not advertise universal acceptance.

Unknown kinds, truncated headers and invalid repair spans return ErrDatagram.
They never count as erasures. Bad source headers, local resource limits, stale
symbols, conflicting identities/equations, and genuinely evicted missing symbols
have separate accounting. The decoder de-duplicates admitted source IDs and
repair IDs within bounded history. Conflicting source bytes, changed repair
identity, contradictory equations, impossible recovered headers, or work/output
budget exhaustion fail the current decoder until an explicit Reset. An error
never exposes a partially decoded batch. Reset discards history and statistics;
a future online caller must not silently reset and then deliver repeated
application frames as new data.

Packed frame lengths are checked before integer conversion or allocation.
Consistent with the frozen vectors, an incomplete packed-frame suffix emits no
partial frame. Fragment groups emit only when all parts are available and are
discarded when their start leaves the fixed assembly window. A valid fragment
whose inferred group start is still in the window extends loss tracking to that
start, even if the prefix was never received. Lost IDs identify missing symbols
leaving the tracked window, not application-frame delivery or retry guarantees.
Prefixes already outside the window are not retroactively reported.

FEC corrects erasures, not arbitrary corruption. A valid-looking changed source
or an underdetermined corrupted repair can produce changed bytes without a
contradiction. There is no MAC in this codec. Future integration must authenticate
the QUIC carrier and validate exactly one complete Queqiao frame, including its
header, payload limit, flags, identity and applicable semantics, before routing
any returned opaque bytes. Only eligible DATA/PACKET payloads may use a future
coded path; control frames must stay on the reliable stream. TCP offsets and UDP association sequence rules remain
responsible for application-level duplicate handling.

Tests consume the existing licensed official protocol1-vectors.json fixture:
all 10 coefficient rows, 5 repair vectors and 12 coded datagram cases. Random
loss/reordering, full-span recovery, delayed repairs, wraparound, ownership,
conflict, malformed input, memory/work limits and fuzz targets supplement those
independent wire anchors. No upstream client, coded or FEC implementation is
linked. The prior experimental TCP half-close unexpected-EOF risk remains open;
this isolated codec does not address or explain it.
