"""The parser runs inside the socket reader loop, so raising ends the session.

An exception here does not produce a bad reading, it stops the client from
reading anything further. That makes "never raises" a stronger property than
"parses correctly", and it is the one the reader loop actually depends on.
"""

import string

import pytest

from xdr_core import parse_event_line

SUFFIXES = ["", "0", "abc", "1,2", ",", ",,", "-1", " ", "99999999999999999999"]


@pytest.mark.parametrize("first", list(string.printable[:95]))
def test_no_first_character_can_end_the_reader_loop(first):
    for suffix in SUFFIXES:
        parse_event_line(first + suffix)


@pytest.mark.parametrize("line", [
    "",
    "\n",
    "\r\n",
    "T",
    "T,",
    "T,,",
    "Tabc",
    "T-",
    "\x00\x01",
    "Ñ0",
    "T87500,10\r",
])
def test_a_malformed_line_does_not_raise(line):
    """Returning None is a valid answer — it means the line is not an event.
    Raising is not, because it takes the reader loop with it."""
    parse_event_line(line)


@pytest.mark.xfail(
    strict=True,
    reason="a frequency payload wider than a float overflows on the kHz to "
           "MHz conversion and raises out of the reader loop",
)
def test_an_oversized_frequency_does_not_raise():
    parse_event_line("T" + "9" * 400)
