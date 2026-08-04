"""Every line the firmware sends must reach the caller as a parsed event.

The parser is written against the protocol as documented, but the bugs it has
had came from the gap between what it handles and what the firmware actually
puts on the wire, in both directions: a handler for a letter that is never
sent, and a letter that is sent and lands in `unknown`.

The letters below are the emitting call sites in the firmware's tuner
controller (`Tuner::feedback` / `feedback2`), not the full protocol table.
Commands the host sends and the tuner only acknowledges are out of scope here.

Keeping this list current is manual. It is worth the upkeep because it is the
only place where the two sides of the protocol are compared at all.
"""

import pytest

from xdr_core import parse_event_line

# letter, sample payload, the state key it must arrive under
EMITTED = [
    ("T", "87500,10", "freq_khz"),
    ("M", "0", "mode"),
    ("V", "12", "daa"),
    ("Y", "78", "volume"),
    ("Q", "1,5", "squelch"),
    ("D", "0", "deemphasis"),
    ("W", "0", "bandwidth"),
    ("A", "0", "agc"),
]


@pytest.mark.parametrize("letter,payload,key", EMITTED)
def test_an_emitted_state_line_arrives_under_its_documented_key(letter, payload, key):
    event = parse_event_line(letter + payload)
    assert event["type"] == "state", (
        f"{letter}{payload} parsed as {event['type']}, so the firmware is "
        f"sending a line the CLI drops"
    )
    assert event["key"] == key


def test_the_quality_interval_line_carries_both_fields():
    """`I<sampling>,<detector>` is emitted as one line with two numbers; a
    parser that keeps it whole leaves both unusable."""
    event = parse_event_line("I500,200")
    assert event["sampling"] == 500
    assert event["detector"] == 200


@pytest.mark.xfail(
    strict=True,
    reason="the firmware emits B<mode> from Tuner.cpp and the parser has no "
           "branch for it, so the output mode is reported as unknown",
)
def test_the_output_mode_line_is_parsed():
    assert parse_event_line("B0")["type"] != "unknown"
