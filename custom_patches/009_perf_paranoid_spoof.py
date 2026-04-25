#!/usr/bin/env python3
"""Spoof perf_event_paranoid for app UIDs to return 3 (most restrictive).

Detection vector confirmed:
  /proc/sys/kernel/perf_event_paranoid on RT Dev / duck kernel is -1
  (fully open). Stock Android user builds default to 2 (OnePlus source)
  or 3 (maximum restriction on some OEMs/GKI builds). ACE / libturinggame
  reads this sysctl to detect a custom/rooted kernel.

  Device value: -1 (any process readable, including uid>=10000 apps)
  Expected on stock user build: 3 (per AOSP hardening guidelines)

Mitigation strategy:
  Replace the .proc_handler of the perf_event_paranoid sysctl entry in
  kernel/sysctl.c with a custom spoof handler that, on read by uid>=10000
  (Android app), returns 3 instead of the real value.

  For root / shell (uid < 10000) and write operations, the real value
  passes through unchanged so perf tooling still works.

Patches:
  kernel/sysctl.c  (kern_table[] perf_event_paranoid entry)
"""

import re
import sys

GUARD = "/* Spoof perf_event_paranoid for app UIDs (uid >= 10000) */"

# Handler function to inject just before kern_table[] definition.
# sysctl_perf_event_paranoid is already declared extern via
# linux/perf_event.h which sysctl.c already includes.
_HANDLER_FUNC = """\
/* Spoof perf_event_paranoid for app UIDs (uid >= 10000) */
static int perf_paranoid_spoof_handler(struct ctl_table *table, int write,
\t\t\t\t       void *buffer, size_t *lenp, loff_t *ppos)
{
\tif (!write && current_uid().val >= 10000) {
\t\tstatic int spoofed_val = 3;
\t\tstruct ctl_table tmp = *table;
\t\ttmp.data = &spoofed_val;
\t\treturn proc_dointvec(&tmp, write, buffer, lenp, ppos);
\t}
\treturn proc_dointvec(table, write, buffer, lenp, ppos);
}

"""

# ── helpers ──────────────────────────────────────────────────────────────────

def load(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()
    except OSError as exc:
        print(f"ERROR: cannot open {path}: {exc}", file=sys.stderr)
        sys.exit(1)


def save(path, content):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)


# ── patch: kernel/sysctl.c → kern_table[] perf_event_paranoid entry ──────────

def patch_sysctl(path):
    """
    1. Insert perf_paranoid_spoof_handler() before kern_table[].
    2. In the perf_event_paranoid sysctl entry, replace
       .proc_handler = proc_dointvec  with  .proc_handler = perf_paranoid_spoof_handler
    """

    content = load(path)

    if GUARD in content:
        print(f"009: {path} already patched, skipping")
        return

    # ── Step 1: inject handler function before kern_table[] ──────────────────
    # Anchor: the exact line that begins the kern_table definition.
    # This appears exactly once in kernel/sysctl.c.
    kern_table_anchor = "static struct ctl_table kern_table[] = {"
    if kern_table_anchor not in content:
        print(
            f"ERROR: kern_table anchor not found in {path}\n"
            f"  Expected: '{kern_table_anchor}'",
            file=sys.stderr,
        )
        sys.exit(1)

    content = content.replace(kern_table_anchor, _HANDLER_FUNC + kern_table_anchor, 1)

    # ── Step 2: replace proc_handler in perf_event_paranoid entry ────────────
    # Pattern matches from the procname line through the proc_handler line
    # within that specific sysctl block. DOTALL so '.' spans newlines.
    #
    # The entry looks like:
    #   {
    #       .procname   = "perf_event_paranoid",
    #       .data       = &sysctl_perf_event_paranoid,
    #       .maxlen     = sizeof(sysctl_perf_event_paranoid),
    #       .mode       = 0644,
    #       .proc_handler   = proc_dointvec,
    #   },
    pattern = re.compile(
        r'(\.procname\s*=\s*"perf_event_paranoid".*?\.proc_handler\s*=\s*)'
        r'proc_dointvec',
        re.DOTALL,
    )

    new_content, count = pattern.subn(
        r'\1perf_paranoid_spoof_handler', content, count=1
    )
    if count == 0:
        print(
            f"ERROR: could not find perf_event_paranoid proc_handler in {path}",
            file=sys.stderr,
        )
        sys.exit(1)

    save(path, new_content)
    print(f"009: {path} (perf_event_paranoid) patched successfully")


# ── main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    patch_sysctl("kernel/sysctl.c")
