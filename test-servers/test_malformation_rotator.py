"""Tests for MalformationRotator."""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from malformation_rotator import MalformationRotator


def _dummy_a():
    return "a"

def _dummy_b():
    return "b"

def _dummy_c():
    return "c"

MALFORMATIONS = [_dummy_a, _dummy_b, _dummy_c]


def test_good_mode_never_evil():
    r = MalformationRotator(MALFORMATIONS, mode="good")
    for _ in range(10):
        is_evil, fn, _ = r.next_action()
        assert not is_evil
        assert fn is None


def test_evil_mode_always_evil():
    r = MalformationRotator(MALFORMATIONS, mode="evil")
    for i in range(6):
        is_evil, fn, _ = r.next_action()
        assert is_evil
        assert fn is not None


def test_evil_mode_rotates():
    r = MalformationRotator(MALFORMATIONS, mode="evil")
    results = []
    for _ in range(6):
        _, fn, _ = r.next_action()
        results.append(fn())
    assert results == ["a", "b", "c", "a", "b", "c"]


def test_both_mode_alternates():
    r = MalformationRotator(MALFORMATIONS, mode="both")
    actions = []
    for _ in range(6):
        is_evil, fn, _ = r.next_action()
        actions.append(is_evil)
    assert actions == [False, True, False, True, False, True]


def test_both_mode_evil_rotates_independently():
    r = MalformationRotator(MALFORMATIONS, mode="both")
    evil_results = []
    for _ in range(8):
        is_evil, fn, _ = r.next_action()
        if is_evil:
            evil_results.append(fn())
    assert evil_results == ["a", "b", "c", "a"]


def test_thread_safety():
    import threading
    r = MalformationRotator(MALFORMATIONS, mode="evil")
    results = []
    lock = threading.Lock()

    def worker():
        for _ in range(100):
            _, fn, _ = r.next_action()
            with lock:
                results.append(fn())

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(results) == 400
    assert all(r in ("a", "b", "c") for r in results)


def test_counter_increments():
    r = MalformationRotator(MALFORMATIONS, mode="both")
    numbers = []
    for _ in range(5):
        _, _, n = r.next_action()
        numbers.append(n)
    assert numbers == [0, 1, 2, 3, 4]
