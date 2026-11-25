"""The control-frame replay window: each sequence number is accepted once, inside a 4096-wide window."""

from transferd.replay import CONTROL_WINDOW, ReplayWindow


def test_a_number_is_accepted_once():
    w = ReplayWindow()
    assert w.accept(0)
    assert not w.accept(0)
    assert w.highest == 0


def test_a_gap_inside_the_window_fills_in_once():
    w = ReplayWindow()
    assert w.accept(1)
    assert w.accept(5)
    assert w.accept(4), "a gap inside the window fills in"
    assert not w.accept(5), "and is then a replay"
    assert w.accept(3)
    assert not w.accept(3)


def test_reordering_inside_the_window_is_tolerated():
    w = ReplayWindow()
    assert w.accept(10)
    assert w.accept(12)
    assert w.accept(11), "11 arrived late but inside the window"
    assert w.accept(9)
    for s in (12, 11, 10, 9):
        assert not w.accept(s)


def test_the_window_is_4096_wide_as_the_spec_says():
    assert CONTROL_WINDOW == 4096
    w = ReplayWindow(CONTROL_WINDOW)
    assert w.accept(0)
    assert w.accept(2000)
    assert w.accept(1000), "1000 is 1000 behind and was never seen"
    assert not w.accept(1000)
    assert not w.accept(0), "0 is still inside the window and was seen"
    assert w.accept(10_000)
    assert not w.accept(2000), "outside the window: refused by age"
    assert not w.accept(5000), "5000 is 5000 behind: outside the window"
    assert w.accept(6000), "6000 is 4000 behind: inside, and unseen"
    assert not w.accept(6000)


def test_a_long_run_stays_bounded_and_refuses_the_old():
    w = ReplayWindow(64)
    for s in range(1000):
        assert w.accept(s)
    assert not w.accept(900), "more than a window behind the newest"
    assert not w.accept(999)
    assert len(w._seen) <= 64
