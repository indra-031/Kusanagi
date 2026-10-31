import os


def load_targets(path: str) -> list:
    """
    Read target URLs from a file, one per line.
    - Blank lines and lines starting with '#' are skipped.
    - Lines without a scheme are prefixed with 'https://'.
    """
    if not os.path.isfile(path):
        raise FileNotFoundError(f"targets file not found: {path}")

    targets = []
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if not line.startswith(("http://", "https://")):
                line = "https://" + line
            targets.append(line)
    return targets