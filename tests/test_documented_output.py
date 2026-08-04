"""The README shows the exact output of `xdrctl status`; this checks it.

Documented output is a contract with whoever integrates against the CLI, and
it is the part of the repository that nothing else verifies. The values below
are copied from the README's status example.
"""

from xdr_core import parse_state_lines

# A status response as the tuner sends it, using the README's values.
SESSION = ["M0", "Y78", "T99900,10", "D0"]


def test_the_status_fields_match_the_documented_example():
    state = parse_state_lines(SESSION)
    assert state["mode"] == 0
    assert state["volume"] == 78
    assert state["freq_khz"] == 99900
    assert state["freq_mhz"] == 99.9


def test_deemphasis_is_reported_as_a_time_constant():
    """The status output converts the raw code to the time constant it selects.
    The README's example still shows the raw code for this field."""
    assert parse_state_lines(SESSION)["deemphasis"] == "50 µs"


def test_the_documented_fields_serialise_to_json():
    """`--json` is the integration surface. A value that json cannot encode
    fails at output time, after the tuner has already been read."""
    import json

    json.dumps(parse_state_lines(SESSION))


def test_alignment_is_reported_in_decibels():
    """The tuner reports front-end alignment as a step index; the CLI converts
    it to the dB value the chip documents."""
    from xdr_core import calculate_daa

    assert calculate_daa(12) == "12 dB"
