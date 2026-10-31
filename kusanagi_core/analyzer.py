from .colors import C


# Status codes that indicate "protected" (not a bypass)
PROTECTED_CODES = {401, 403}

# Status codes that usually mean "your request is broken", not a real bypass
FALSE_POSITIVE_CODES = {
    400,  # Bad Request
    405,  # Method Not Allowed
    406,  # Not Acceptable
    408,  # Request Timeout
    411,  # Length Required
    413,  # Payload Too Large
    414,  # URI Too Long
    415,  # Unsupported Media Type
    429,  # Too Many Requests
    431,  # Request Header Fields Too Large
    501,  # Not Implemented
    505,  # HTTP Version Not Supported
}

# If a new response is within this many bytes of baseline size,
# it is considered "the same page" (still blocked).
BASELINE_SIZE_TOLERANCE = 30


def classify(status: int, size: int, baseline: dict):
    """
    Returns (tag, color) or (None, None).

    Rules:
      1. 401/403 -> not a bypass
      2. Known false-positive codes -> not a bypass
      3. Same size as baseline -> not a bypass
      4. Otherwise classify by status range
    """
    # Rule 1: protected
    if status in PROTECTED_CODES:
        return None, None

    # Rule 2: known "broken request" codes
    if status in FALSE_POSITIVE_CODES:
        return None, None

    base_size = baseline.get("size", 0)

    # Rule 3: same size as baseline -> still blocked
    if base_size > 0 and abs(size - base_size) <= BASELINE_SIZE_TOLERANCE:
        return None, None

    # Rule 4: classify by range
    if 200 <= status < 300:
        return "BYPASS-2xx", C.GREEN
    if 300 <= status < 400:
        return "BYPASS-3xx", C.CYAN
    if 400 <= status < 500:
        return "BYPASS-4xx?", C.YELLOW  # low confidence
    if 500 <= status < 600:
        return "BYPASS-5xx", C.MAGENTA
    return "BYPASS-???", C.MAGENTA