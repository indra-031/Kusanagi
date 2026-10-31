import os
from typing import List


def _iter_lines(path: str):
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.rstrip("\n").rstrip("\r")
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            yield stripped


def load_headers(path: str) -> List[str]:
    """Load header payloads, dedupe preserving order."""
    if not os.path.isfile(path):
        raise FileNotFoundError(f"headers file not found: {path}")
    seen, out = set(), []
    for line in _iter_lines(path):
        if ":" not in line and line != "__NONE__":
            continue
        if line in seen:
            continue
        seen.add(line)
        out.append(line)
    return out


def load_methods(path: str) -> List[str]:
    if not os.path.isfile(path):
        raise FileNotFoundError(f"methods file not found: {path}")
    return [m.upper() for m in _iter_lines(path)]


def load_path_templates(path: str) -> List[str]:
    if not os.path.isfile(path):
        raise FileNotFoundError(f"paths file not found: {path}")
    return list(_iter_lines(path))


def load_lines(path: str) -> List[str]:
    """Generic loader: returns raw non-comment lines as-is."""
    if not os.path.isfile(path):
        raise FileNotFoundError(f"file not found: {path}")
    return list(_iter_lines(path))


def render_path(template: str, base_path: str) -> str:
    base = base_path.rstrip("/") or "/"
    name = base.lstrip("/")

    enc = name.replace("a", "%61", 1) if "a" in name else name
    cap = (name[:1].upper() + name[1:]) if name else name
    upper = name.upper()

    return (template
            .replace("{base}", base)
            .replace("{name}", name)
            .replace("{upper}", upper)
            .replace("{cap}", cap)
            .replace("{enc}", enc))


def render_header(line: str, path: str) -> str:
    no_slash = path.lstrip("/")
    return (line
            .replace("{path_no_slash}", no_slash)
            .replace("{path}", path))