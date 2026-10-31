"""
Resume manager.

Tracks which targets have already been fully tested so that a
subsequent run can skip them. Uses a simple line-delimited file.
"""

import os
import threading


class ResumeManager:
    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        self.done = self._load()

    def _load(self):
        if not os.path.isfile(self.path):
            return set()
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                return {line.strip() for line in f if line.strip()}
        except Exception:
            return set()

    def is_done(self, target):
        return target in self.done

    def mark_done(self, target):
        with self._lock:
            if target in self.done:
                return
            self.done.add(target)
            try:
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(target + "\n")
            except Exception:
                pass

    def reset(self):
        with self._lock:
            self.done.clear()
            try:
                if os.path.isfile(self.path):
                    os.remove(self.path)
            except Exception:
                pass

    def count(self):
        return len(self.done)