import pytest

from transferd.bincode import Reader, Writer
from transferd.errors import DecodeError


def test_integers_are_fixed_width_little_endian():
    w = Writer()
    w.u16(0x0102)
    w.u32(0x03040506)
    w.u64(0x0708090A0B0C0D0E)
    assert w.getvalue() == bytes.fromhex("0201" "06050403" "0e0d0c0b0a090807")


def test_a_string_is_a_u64_length_then_utf8():
    w = Writer()
    w.string("ab")
    assert w.getvalue() == bytes.fromhex("0200000000000000" "6162")


def test_option_is_a_tag_byte_then_the_value():
    w = Writer()
    w.option(None, lambda w_, v: w_.u8(v))
    w.option(5, lambda w_, v: w_.u8(v))
    assert w.getvalue() == bytes.fromhex("00" "01" "05")


def test_round_trip_and_trailing_bytes_are_ignored():
    w = Writer()
    w.u32(7)
    w.string("hi")
    r = Reader(w.getvalue() + b"\xff\xff")
    assert r.u32() == 7
    assert r.string() == "hi"
    assert r.remaining() == 2


def test_a_length_past_the_end_is_refused():
    with pytest.raises(DecodeError):
        Reader(bytes.fromhex("ffffffffffffffff00")).bytes_()


def test_bool_bytes_other_than_zero_and_one_are_refused():
    with pytest.raises(DecodeError):
        Reader(b"\x02").boolean()
