import threading

from .colors import C


def _format_entry(desc, method, url):
    if desc.startswith("H: "):
        return desc[3:]
    if desc.startswith("Host: "):
        return desc
    if "(via POST)" in desc:
        return desc
    if desc.startswith("HTTP/"):
        return desc
    if url:
        return url
    return desc


class Reporter:
    def __init__(self, show_all=False, output_path=""):
        self.show_all = show_all
        self.total = 0
        self.bypass = 0
        self.redirect = 0
        self.low_conf = 0
        self.diff = 0
        self.hits = []
        self.confident_hits = []
        self.low_conf_hits = []
        self._out = open(output_path, "w", encoding="utf-8") if output_path else None
        self._lock = threading.Lock()

    def section(self, title):
        print(f"\n{C.BOLD}{C.BLUE}--- [ {title} ] "
              f"---------------------------------{C.RESET}")

    def info(self, label, value, color=""):
        print(f"{C.BOLD}[*]{C.RESET} {label:<10}: {color}{value}{C.RESET}")

    def error(self, msg):
        with self._lock:
            print(f"  {C.RED}[ERR]{C.RESET} {msg}")

    def _register(self, entry):
        tag = entry["tag"]
        if not tag:
            return

        self.hits.append(entry)

        if tag == "BYPASS-4xx?":
            self.low_conf += 1
            self.low_conf_hits.append(entry)
        elif tag in ("DIFF", "SIZE-DIFF"):
            self.diff += 1
        elif tag == "REDIRECT":
            self.redirect += 1
            self.confident_hits.append(entry)
        else:
            self.bypass += 1
            self.confident_hits.append(entry)

    def _write_out(self, entry):
        if self._out:
            tag = entry["tag"] or "-"
            self._out.write(
                f"{entry['status']}\t{entry['method']}\t"
                f"{entry['desc']}\t{tag}\t{entry['size']}\n"
            )

    def report(self, desc, method, status, size, tag, color, url="", headers=None):
        with self._lock:
            self.total += 1
            entry = {
                "status": status,
                "method": method,
                "desc": desc,
                "tag": tag,
                "size": size,
                "url": url,
                "headers": headers or {},
            }
            self._register(entry)

            if tag or self.show_all:
                display = _format_entry(desc, method, url)
                color = color or C.DIM
                print(f"  {color}[{status:>3}]{C.RESET} "
                      f"{C.DIM}{method:<6}{C.RESET} "
                      f"{display:<75.75} "
                      f"{color}{tag or '':<12}{C.RESET} "
                      f"{C.DIM}{size}B{C.RESET}")

            self._write_out(entry)

    def track_only(self, desc, method, status, size, tag, url="", headers=None):
        with self._lock:
            self.total += 1
            entry = {
                "status": status,
                "method": method,
                "desc": desc,
                "tag": tag,
                "size": size,
                "url": url,
                "headers": headers or {},
            }
            self._register(entry)
            self._write_out(entry)

    def summary(self):
        print(f"\n{C.BOLD}{C.BLUE}--- [ Summary ] "
              f"---------------------------------{C.RESET}")
        print(f"  {'Total tested':<28} {C.BOLD}{self.total}{C.RESET}")
        print(f"  {'Confident bypasses':<28} {C.GREEN}{len(self.confident_hits)}{C.RESET}")
        print(f"  {'Low-confidence (4xx)':<28} {C.YELLOW}{len(self.low_conf_hits)}{C.RESET}")
        print(f"  {'Other (diff/size)':<28} {C.MAGENTA}{self.diff}{C.RESET}")

        if self.confident_hits:
            print(f"\n{C.BOLD}{C.GREEN}Top confident candidates:{C.RESET}")
            for h in self.confident_hits[:10]:
                display = _format_entry(h["desc"], h["method"], h["url"])
                print(f"  -> [{h['status']}] {h['method']} {display}  "
                      f"({h['tag']}, {h['size']}B)")

        if self.low_conf_hits:
            print(f"\n{C.BOLD}{C.YELLOW}Low-confidence (verify manually):{C.RESET}")
            for h in self.low_conf_hits[:3]:
                display = _format_entry(h["desc"], h["method"], h["url"])
                print(f"  ? [{h['status']}] {h['method']} {display}  "
                      f"({h['tag']}, {h['size']}B)")
            if len(self.low_conf_hits) > 3:
                print(f"  {C.DIM}... and {len(self.low_conf_hits) - 3} more{C.RESET}")

        print(f"\n{C.DIM}  [!] Verify results manually before reporting.{C.RESET}")

    def close(self):
        if self._out:
            self._out.close()