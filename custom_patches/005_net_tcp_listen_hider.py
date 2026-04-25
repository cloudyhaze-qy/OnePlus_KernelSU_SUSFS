#!/usr/bin/env python3
"""Hide TCP_LISTEN entries from /proc/net/tcp and /proc/net/tcp6 for app UIDs.

For readers with uid >= 10000, skip TCP LISTEN socket entries so
KernelSU's internal service ports (127.0.0.1:10156/10157, etc.) are
invisible.  Non-LISTEN entries (ESTABLISHED, TIME_WAIT, …) are unchanged.

Patches:
  net/ipv4/tcp_ipv4.c  (tcp4_seq_show)
  net/ipv6/tcp_ipv6.c  (tcp6_seq_show)
"""

import re
import sys

GUARD = "/* Hide TCP_LISTEN from app UIDs (uid >= 10000) */"

FILTER_BLOCK = (
    "\n"
    "\t" + GUARD + "\n"
    "\tif (current_uid().val >= 10000 && sk->sk_state == TCP_LISTEN)\n"
    "\t\treturn 0;\n"
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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


def patch_seq_show(path, timewait_fn):
    """Insert FILTER_BLOCK right after 'st = seq->private;' in the seq_show
    function that dispatches to *timewait_fn* for TIME_WAIT sockets."""

    content = load(path)

    if GUARD in content:
        print(f"005: {path} already patched, skipping")
        return

    # Anchor: st = seq->private; <optional blank line>
    #         if (sk->sk_state == TCP_TIME_WAIT)
    #             <timewait_fn>(...)
    pattern = re.compile(
        r"(\tst = seq->private;[ \t]*\n)"
        r"(\n\tif \(sk->sk_state == TCP_TIME_WAIT\)\n"
        r"\t\t" + re.escape(timewait_fn) + r")"
    )

    m = pattern.search(content)
    if not m:
        print(
            f"ERROR: anchor not found in {path}\n"
            f"  Looking for: st = seq->private; + {timewait_fn}",
            file=sys.stderr,
        )
        sys.exit(1)

    new_content = pattern.sub(
        lambda x: x.group(1) + FILTER_BLOCK + x.group(2),
        content,
        count=1,
    )

    save(path, new_content)
    print(f"005: {path} patched successfully")


# ---------------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------------

patch_seq_show("net/ipv4/tcp_ipv4.c", "get_timewait4_sock(v, seq, st->num)")
patch_seq_show("net/ipv6/tcp_ipv6.c", "get_timewait6_sock(seq, v, st->num)")
