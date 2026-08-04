"""A numeric state value has to survive arithmetic downstream.

Multi-field lines such as `T<khz>,<step>` arrive as one string. Left whole, the
value still prints and still compares, so the CLI looks correct while every
consumer that does arithmetic on it fails: `float()` raises, and a field
derived from it stays empty.

These pin the type at the boundary rather than at each call site, because the
call sites are in other repositories.
"""

import pytest

from xdr_core import parse_event_line

NUMERIC = ["T87500,10", "M0", "Y78", "D0", "A0", "W0", "Z0", "G0", "V12", "C90"]


@pytest.mark.parametrize("line", NUMERIC)
def test_a_numeric_state_value_can_be_used_as_a_number(line):
    value = parse_event_line(line)["value"]
    float(value)


def test_a_tuned_frequency_reports_megahertz():
    event = parse_event_line("T87500,10")
    assert event["value"] == 87500
    assert event["freq_mhz"] == 87.5
    assert event["step_khz"] == 10


def test_a_frequency_without_a_step_still_reports_megahertz():
    """The single-field form the parser handled before multi-field lines were
    considered. It is not what the tuner sends today, and it still has to work
    for anything replaying older captures."""
    event = parse_event_line("T87500")
    assert event["value"] == 87500
    assert event["freq_mhz"] == 87.5


@pytest.mark.parametrize("line", ["T", "Tabc", "T,"])
def test_an_unparseable_frequency_keeps_the_raw_value(line):
    """Nothing validates the payload before it reaches here, so a line that is
    not a number must pass through rather than raise."""
    event = parse_event_line(line)
    assert isinstance(event["value"], str)
    assert "freq_mhz" not in event


def test_a_blank_frequency_reads_as_zero():
    """A tuner with nothing stored answers `T0`. Read as anything but 0 it is
    indistinguishable from a tuner that failed to report."""
    assert parse_event_line("T0,10")["value"] == 0
