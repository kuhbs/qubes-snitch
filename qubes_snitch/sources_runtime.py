# Runtime source identity helpers for qubes-snitchd
# These functions keep dom0/QubesDB source tracking out of the executable daemon wiring

from qubes_snitch import config
from qubes_snitch import alerts_runtime
from qubes_snitch import policy_runtime


def parse_sources_output(ctx, text):
    # Config validation requires this key, so source parsing must not invent a Python fallback
    return config.parse_sources_output(text, ctx.SOURCE_SERVICE, ctx.CONFIG["default_disposable_vm_name"])


def source_refresh_error_reason(error):
    reason = str(error)
    if not reason or reason == "0":
        return ""
    return f" REASON={reason}"


def query_dom0_sources(ctx):
    # qrexec-client-vm asks dom0 for the current VM/IP/label table without copying stale state into sys-snitch
    result = ctx.subprocess.run(
        ["qrexec-client-vm", "dom0", ctx.SOURCE_SERVICE],
        check=True,
        text=True,
        stdout=ctx.subprocess.PIPE,
        stderr=ctx.subprocess.PIPE,
        timeout=5,
    )
    return parse_sources_output(ctx, result.stdout)


def ensure_all_known_rule_entries(ctx):
    # Every known VM source needs a rule bucket so prompt decisions can be saved by VM name immediately
    for source in ctx.SOURCES_BY_NAME:
        policy_runtime.ensure_rule_entry(ctx, source)


def refresh_sources_and_nft(ctx, force=False):
    # Rate-limit QubesDB bursts before qrexec so repeated events do not run slow dom0 calls unnecessarily
    now = ctx.time.monotonic()
    if not force and now - ctx.LAST_SOURCE_REFRESH < ctx.SOURCE_REFRESH_INTERVAL:
        return False
    try:
        # qrexec can wait on dom0, so run it before POLICY_LOCK to keep packet handling and CLI answers responsive
        new_sources_by_name, new_sources_by_ip, new_labels, new_display_by_ip = query_dom0_sources(ctx)
    except (ctx.subprocess.TimeoutExpired, ctx.subprocess.CalledProcessError, OSError, SystemExit) as error:
        alerts_runtime.fatal_security_alert(ctx, ("source-refresh-failed",), f"source identity refresh failed{source_refresh_error_reason(error)}")
        raise
    with ctx.POLICY_LOCK:
        old_sources_by_name = {source: list(ips) for source, ips in ctx.SOURCES_BY_NAME.items()}
        ctx.LAST_SOURCE_REFRESH = now
        if (new_sources_by_name, new_sources_by_ip, new_labels, new_display_by_ip) == (ctx.SOURCES_BY_NAME, ctx.SOURCES_BY_IP, ctx.SOURCE_LABELS, ctx.SOURCE_DISPLAY_BY_IP):
            return False
        ctx.SOURCES_BY_NAME, ctx.SOURCES_BY_IP, ctx.SOURCE_LABELS, ctx.SOURCE_DISPLAY_BY_IP = new_sources_by_name, new_sources_by_ip, new_labels, new_display_by_ip
        policy_runtime.cleanup_reused_numbered_dispvm_entries(ctx, old_sources_by_name)
        policy_runtime.cleanup_disposable_rule_entries(ctx)
        ensure_all_known_rule_entries(ctx)
        policy_runtime.load_nft(ctx)
        return True


def qubesdb_source_event(path):
    # Match the same broad QubesDB paths sys-firewall watches for connected IP and firewall updates
    return path == "/connected-ips" or path.startswith("/qubes-firewall/")


def qubesdb_source_watcher(ctx):
    # QubesDB is the push signal; qrexec fetches richer VM metadata only after a signal
    try:
        qdb = ctx.qubesdb.QubesDB()
        for path in ctx.QDB_WATCH_PATHS:
            qdb.watch(path)
        while True:
            path = qdb.read_watch()
            if qubesdb_source_event(path):
                refresh_sources_and_nft(ctx, force=True)
    except BaseException as error:
        alerts_runtime.fatal_security_alert(ctx, ("qubesdb-watcher-failed",), f"QubesDB source watcher failed REASON={error}")


def refresh_sources_required(ctx):
    # Startup needs the trusted source map before real policy loads, but qrexec still runs outside POLICY_LOCK
    try:
        new_sources_by_name, new_sources_by_ip, new_labels, new_display_by_ip = query_dom0_sources(ctx)
    except (ctx.subprocess.TimeoutExpired, ctx.subprocess.CalledProcessError, OSError, SystemExit) as error:
        alerts_runtime.fatal_security_alert(ctx, ("source-refresh-failed",), f"source identity refresh failed{source_refresh_error_reason(error)}")
        raise
    with ctx.POLICY_LOCK:
        ctx.LAST_SOURCE_REFRESH = ctx.time.monotonic()
        ctx.SOURCES_BY_NAME, ctx.SOURCES_BY_IP, ctx.SOURCE_LABELS, ctx.SOURCE_DISPLAY_BY_IP = new_sources_by_name, new_sources_by_ip, new_labels, new_display_by_ip
        policy_runtime.cleanup_disposable_rule_entries(ctx)
        ensure_all_known_rule_entries(ctx)
        policy_runtime.load_nft(ctx)
    return True

