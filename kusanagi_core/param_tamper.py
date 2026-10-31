"""
Targeted parameter tampering tests.

Extracts existing query parameters from the target URL and applies:
  - HTTP Parameter Pollution (HPP / duplicate params)
  - Value tampering (0, -1, null, true, false, ...)
  - Type juggling (integer -> array, string -> array)
  - Case variation on parameter names
  - Whitespace / URL-encoding tricks
  - Parameter addition (admin, role, debug, ...)
"""

from urllib.parse import (
    urlparse, parse_qs, urlencode, urlunparse, quote
)


# Values used to replace existing parameter values
TAMPER_VALUES = [
    "0", "-1", "1", "9999999",
    "null", "undefined", "none", "nil",
    "true", "false",
    "admin", "root", "administrator",
    "1e1", "0x1", "0b1",
    "0000", "1.0", "-0",
    " ", "", "%00", "NaN",
]

# Extra params appended to the URL (parameter addition attack)
EXTRA_PARAMS = [
    ("admin", "1"),
    ("admin", "true"),
    ("isAdmin", "1"),
    ("is_admin", "true"),
    ("debug", "1"),
    ("debug", "true"),
    ("test", "1"),
    ("internal", "1"),
    ("role", "admin"),
    ("access", "granted"),
    ("bypass", "1"),
    ("token", "1"),
    ("auth", "1"),
    ("source", "internal"),
    ("from", "localhost"),
]

# Duplicate value used for HPP (appended as a second instance)
HPP_DUP_VALUES = [
    "0", "1", "-1", "admin", "true", "false", "null", "",
]


def _rebuild_url(parsed, new_query: str) -> str:
    """Replace the query string of a parsed URL and rebuild it."""
    return urlunparse(parsed._replace(query=new_query))


def _iter_existing_param_tests(target: str):
    """
    Yield (desc, url) tuples for tampering existing query parameters.
    """
    parsed = urlparse(target)
    if not parsed.query:
        return

    # parse_qs returns a dict {name: [values]}. keep_blank_values keeps
    # empty-value params.
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return

    # --- For each existing parameter ---
    for name, values in params.items():
        original = values[0] if values else ""

        # 1) HPP: duplicate the parameter with different values
        for dup in HPP_DUP_VALUES:
            if dup == original:
                continue
            # Preserve original first, append second
            new_pairs = []
            for p_name, p_values in params.items():
                for v in p_values:
                    new_pairs.append((p_name, v))
                if p_name == name:
                    new_pairs.append((p_name, dup))
            new_query = urlencode(new_pairs)
            new_url = _rebuild_url(parsed, new_query)
            yield (
                f"HPP: {name}={original}&{name}={dup}",
                new_url,
            )

        # 2) HPP (reverse order): dup first, original last
        for dup in ["0", "1", "admin"]:
            new_pairs = []
            for p_name, p_values in params.items():
                if p_name == name:
                    new_pairs.append((p_name, dup))
                for v in p_values:
                    new_pairs.append((p_name, v))
            new_query = urlencode(new_pairs)
            new_url = _rebuild_url(parsed, new_query)
            yield (
                f"HPP-rev: {name}={dup}&{name}={original}",
                new_url,
            )

        # 3) Array syntax: id=1 -> id[]=1
        arr_pairs = []
        for p_name, p_values in params.items():
            if p_name == name:
                for v in p_values:
                    arr_pairs.append((f"{p_name}[]", v))
            else:
                for v in p_values:
                    arr_pairs.append((p_name, v))
        yield (
            f"Array: {name}[]={original}",
            _rebuild_url(parsed, urlencode(arr_pairs)),
        )

        # 4) Indexed array syntax: id[0]=1
        idx_pairs = []
        for p_name, p_values in params.items():
            if p_name == name:
                for i, v in enumerate(p_values):
                    idx_pairs.append((f"{p_name}[{i}]", v))
            else:
                for v in p_values:
                    idx_pairs.append((p_name, v))
        yield (
            f"Indexed: {name}[0]={original}",
            _rebuild_url(parsed, urlencode(idx_pairs)),
        )

        # 5) Value tampering
        for new_val in TAMPER_VALUES:
            if new_val == original:
                continue
            new_pairs = []
            for p_name, p_values in params.items():
                if p_name == name:
                    new_pairs.append((p_name, new_val))
                else:
                    for v in p_values:
                        new_pairs.append((p_name, v))
            new_query = urlencode(new_pairs)
            yield (
                f"Value: {name}={new_val}",
                _rebuild_url(parsed, new_query),
            )

        # 6) Parameter name case variation
        if name.lower() != name.upper():
            for case_variant in (name.upper(), name.lower(),
                                 name.capitalize()):
                if case_variant == name:
                    continue
                new_pairs = []
                for p_name, p_values in params.items():
                    use_name = case_variant if p_name == name else p_name
                    for v in p_values:
                        new_pairs.append((use_name, v))
                yield (
                    f"Name-case: {case_variant}={original}",
                    _rebuild_url(parsed, urlencode(new_pairs)),
                )

        # 7) Trailing whitespace on the value
        for suffix in (" ", "\t", "%20", "%09"):
            new_val = f"{original}{suffix}"
            new_pairs = []
            for p_name, p_values in params.items():
                if p_name == name:
                    new_pairs.append((p_name, new_val))
                else:
                    for v in p_values:
                        new_pairs.append((p_name, v))
            yield (
                f"Whitespace: {name}={new_val!r}",
                _rebuild_url(parsed, urlencode(new_pairs)),
            )


def _iter_extra_param_tests(target: str):
    """Yield (desc, url) tuples for adding brand-new parameters."""
    parsed = urlparse(target)
    base_params = parse_qs(parsed.query, keep_blank_values=True)

    for key, val in EXTRA_PARAMS:
        new_pairs = []
        for p_name, p_values in base_params.items():
            for v in p_values:
                new_pairs.append((p_name, v))
        new_pairs.append((key, val))
        new_query = urlencode(new_pairs)
        new_url = _rebuild_url(parsed, new_query)
        yield (f"Add: {key}={val}", new_url)


def generate_param_tests(target: str):
    """
    Generate all parameter-tampering URLs for a target.
    Returns a list of (description, url).
    """
    tests = []
    tests.extend(_iter_existing_param_tests(target))
    tests.extend(_iter_extra_param_tests(target))

    # Deduplicate by URL
    seen = set()
    unique = []
    for desc, url in tests:
        if url in seen:
            continue
        seen.add(url)
        unique.append((desc, url))
    return unique