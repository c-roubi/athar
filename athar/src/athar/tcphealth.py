"""TCP health analysis with Wireshark-style sequence logic.

Reimplements the core of Wireshark's TCP sequence analysis so retransmissions,
fast retransmissions, out-of-order segments, zero-window and reset events are
distinguished the way an analyst expects, rather than by naive seq repetition.

The key rule (from Wireshark's tcp_analyze_sequence_number): a segment that
carries data (or SYN/FIN) but does **not** advance the sequence number is one of
retransmission / fast-retransmission / out-of-order. They are told apart using an
RTT threshold derived from the connection's initial RTT (the SYN -> SYN/ACK gap),
falling back to 3 ms, and the duplicate-ACK count in the reverse direction:

* arrived within the RTT threshold of the highest-seq segment  -> out-of-order
* preceded by >= 3 duplicate ACKs                              -> fast retransmission
* otherwise                                                    -> retransmission

State is O(number of directions), so it stays streaming-friendly.
"""

from __future__ import annotations

from dataclasses import dataclass, field

_SYN, _RST, _ACK, _FIN = 0x02, 0x04, 0x10, 0x01
_OOO_FALLBACK_RTT = 0.003   # 3 ms, Wireshark's default when iRTT is unknown
_DUP_ACK_FASTRETX = 3       # duplicate ACKs that trigger a fast retransmission


@dataclass
class _DirState:
    next_seq: int = -1          # next expected sequence number (highest seen + len)
    highest_seq: int = -1
    highest_seq_ts: float = 0.0
    last_ack: int = -1
    dup_ack_count: int = 0
    syn_ts: float = 0.0         # for initial-RTT measurement


@dataclass
class TCPHealth:
    """Accumulated TCP anomaly counts using Wireshark-style logic."""

    retransmissions: int = 0
    fast_retransmissions: int = 0
    out_of_order: int = 0
    resets: int = 0
    zero_window: int = 0
    syns: int = 0

    _dirs: dict[tuple[str, int, str, int], _DirState] = field(default_factory=dict)
    _irtt: dict[frozenset[tuple[str, int]], float] = field(default_factory=dict)
    per_flow: dict[tuple[str, str, int, int], dict[str, int]] = field(default_factory=dict)

    def observe(  # noqa: PLR0913
            self, ts: float, src: str, dst: str, sport: int, dport: int,
            flags: int, seq: int, ack: int, window: int, payload_len: int) -> None:
        fwd = (src, sport, dst, dport)
        state = self._dirs.setdefault(fwd, _DirState())
        rev = self._dirs.get((dst, dport, src, sport))
        conv = frozenset({(src, sport), (dst, dport)})

        canon = ((src, dst, sport, dport) if (src, sport) <= (dst, dport)
                 else (dst, src, dport, sport))
        tally = self.per_flow.setdefault(canon, {})

        def bump(kind: str) -> None:
            tally[kind] = tally.get(kind, 0) + 1

        # --- resets, zero-window, SYN/iRTT bookkeeping -----------------------
        if flags & _RST:
            self.resets += 1
            bump("resets")
        if flags & _SYN and not (flags & _ACK):
            self.syns += 1
            state.syn_ts = ts
        if flags & _SYN and flags & _ACK and rev is not None and rev.syn_ts:
            self._irtt[conv] = ts - rev.syn_ts        # SYN/ACK - SYN
        if window == 0 and not (flags & (_RST | _SYN)):
            self.zero_window += 1
            bump("zero_window")

        # --- duplicate ACK tracking (reverse-direction signal) ---------------
        if flags & _ACK and payload_len == 0 and not (flags & (_SYN | _FIN)):
            if ack == state.last_ack and window != 0:
                state.dup_ack_count += 1
            else:
                state.dup_ack_count = 0
        state.last_ack = ack if (flags & _ACK) else state.last_ack

        # --- retransmission / fast-retx / out-of-order -----------------------
        seg_advances = payload_len > 0 or (flags & (_SYN | _FIN))
        if not seg_advances:
            return

        end_seq = seq + payload_len + (1 if flags & (_SYN | _FIN) else 0)
        # Wireshark's rule: a data/SYN/FIN segment that does NOT advance the
        # sequence number (all of its bytes are already past) is one of
        # retransmission / fast-retransmission / out-of-order.
        if state.next_seq >= 0 and end_seq <= state.next_seq:
            threshold = self._irtt.get(conv, _OOO_FALLBACK_RTT)
            if state.highest_seq_ts and (ts - state.highest_seq_ts) <= threshold:
                self.out_of_order += 1
                bump("out_of_order")
            elif rev is not None and rev.dup_ack_count >= _DUP_ACK_FASTRETX:
                self.fast_retransmissions += 1
                bump("fast_retransmissions")
            else:
                self.retransmissions += 1
                bump("retransmissions")
        else:
            if end_seq > state.highest_seq:
                state.highest_seq = end_seq
                state.highest_seq_ts = ts
            state.next_seq = max(state.next_seq, end_seq)

    def summary(self) -> dict[str, int]:
        return {
            "retransmissions": self.retransmissions,
            "fast_retransmissions": self.fast_retransmissions,
            "out_of_order": self.out_of_order,
            "resets": self.resets,
            "zero_window": self.zero_window,
            "syns": self.syns,
        }
