"""Shared malformation rotation engine for evil test servers."""

import os
import threading


class MalformationRotator:
    """Thread-safe rotating malformation selector.

    In 'evil' mode, every request gets the next malformation.
    In 'both' mode, even requests get good responses, odd get evil.
    In 'good' mode, the rotator is not used.
    """

    def __init__(self, malformations, mode="both", state_file=None):
        self.malformations = malformations
        self.mode = mode
        self._counter = 0
        self._lock = threading.Lock()
        self._state_file = state_file

    def next_action(self):
        """Return (is_evil, malformation_fn_or_None, request_number).

        is_evil=False means serve a normal response.
        is_evil=True means call the returned malformation function.
        """
        with self._lock:
            n = self._counter
            self._counter += 1

        if self.mode == "good":
            return False, None, n

        if self.mode == "evil":
            fn = self.malformations[n % len(self.malformations)]
            return True, fn, n

        # "both" — even=good, odd=evil
        if n % 2 == 0:
            return False, None, n
        else:
            evil_index = n // 2
            fn = self.malformations[evil_index % len(self.malformations)]
            return True, fn, n

    def log_action(self, protocol, n, is_evil, name=""):
        """Log to stderr and write state file for post-hoc attribution."""
        import sys
        if is_evil:
            print(f"[evil] {protocol} request #{n}: malformation={name}",
                  file=sys.stderr)
        else:
            print(f"[good] {protocol} request #{n}: normal response",
                  file=sys.stderr)
        # Write state file for the Rust executor to read
        if self._state_file:
            try:
                with open(self._state_file, "w") as f:
                    f.write(name if is_evil else "good")
            except Exception:
                pass
