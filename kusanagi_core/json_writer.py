"""
JSON results writer.

Accumulates results across multiple targets and writes them atomically
to a single JSON file after each target completes.
"""

import json
import os
import threading
from datetime import datetime


class JsonWriter:
    def __init__(self, path):
        self.path = path
        self.data = []
        self._lock = threading.Lock()

    def add_target(self, target, reporter, baseline=None):
        """Append a target's results."""
        with self._lock:
            entry = {
                "target": target,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "baseline": baseline or {},
                "summary": {
                    "total": reporter.total,
                    "confident": len(reporter.confident_hits),
                    "low_conf": len(reporter.low_conf_hits),
                    "diff": reporter.diff,
                },
                "hits": [],
            }

            for h in (reporter.confident_hits + reporter.low_conf_hits):
                entry["hits"].append({
                    "status": h.get("status"),
                    "method": h.get("method"),
                    "desc": h.get("desc"),
                    "url": h.get("url"),
                    "tag": h.get("tag"),
                    "size": h.get("size"),
                })

            self.data.append(entry)

        self._save()

    def _save(self):
        with self._lock:
            tmp = self.path + ".tmp"
            try:
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump(self.data, f, indent=2, ensure_ascii=False)
                os.replace(tmp, self.path)
            except Exception as e:
                print(f"[!] Could not write JSON: {e}")

    def close(self):
        self._save()