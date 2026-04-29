#!/usr/bin/env python3
"""Hide RT Dev KPM char device (major=451) uevent broadcast.

When device_create() is called, kernel broadcasts uevent via kobject_uevent()
to all listening NETLINK_KOBJECT_UEVENT sockets. The uevent payload contains:
  ACTION=add
  DEVPATH=/class/rhJgD/rhJgD
  SUBSYSTEM=rhJgD
  (where rhJgD is the 6-char device name)

ACE / libturinggame.so monitors NETLINK sockets and extracts device name
from SUBSYSTEM field. This happens BEFORE any VFS-layer hiding patches
(stat/open/getdents64) take effect.

We filter at the source: skip uevent broadcast for devices whose:
  - device name is 6-character alphanumeric (matches RT Dev pattern)
  - OR major number is 451

Injection point: lib/kobject.c → kobject_uevent()
  After building the envp[] array but before netlink_unicast().

NOTE: This patch also covers the inotify notification path, because
inotify events flow through the same device_add() → kobject_uevent()
code path.

Patches:
  lib/kobject.c  (kobject_uevent)
"""

import re
import sys
import os

GUARD = "/* Hide RT Dev (major=451) uevent broadcast */"

# Filter block: skip uevent for RT Dev devices
_HIDE_BLOCK = """
{GUARD}
{{
    int i;
    for (i = 0; envp[i]; i++) {{
        if (strncmp(envp[i], "SUBSYSTEM=", 10) == 0) {{
            char *name = envp[i] + 10;
            // Check SUBSYSTEM=6-char alphanumeric (RT Dev pattern)
            if (strlen(name) == 6 &&
                ((name[0] >= 'a' && name[0] <= 'z') ||
                 (name[0] >= 'A' && name[0] <= 'Z') ||
                 (name[0] >= '0' && name[0] <= '9'))) {{
                // Skip uevent broadcast for RT Dev
                return 0;
            }}
        }}
        if (strncmp(envp[i], "MAJOR=", 6) == 0) {{
            if (simple_strtoul(envp[i] + 6, NULL, 10) == 451) {{
                return 0;
            }}
        }}
    }}
}}
""".format(GUARD=GUARD)


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


# -- patch: lib/kobject.c → kobject_uevent ---------------------------

def patch_kobject_uevent(path):
    """Insert RT Dev filter in kobject_uevent().

    We insert right after the envp[] loop starts (if (!envp[i]) to skip
    uevent for RT Dev devices before netlink_unicast().

    In Linux 5.10 lib/kobject.c the relevant section:

        for (i = 0; envp[i]; i++)
            len += strlen(envp[i]) + 1;

    We inject BEFORE this loop or inside it, checking SUBSYSTEM and MAJOR.
    """

    content = load(path)

    if GUARD in content:
        print(f"020: {path} already patched, skipping")
        return

    # Anchor: the envp loop + len calculation
    pattern = re.compile(
        r"(\tfor \(i = 0; envp\[i\]; i\+\+\)\n"
        r"\t\tlen \+= strlen\(envp\[i\]\) \+ 1;)"
    )

    if not pattern.search(content):
        # Try alternative anchor: for (i = 0; envp[i]; i++)
        pattern = re.compile(r"(\tfor \(i = 0; envp\[i\]; i\+\+\))")
        if not pattern.search(content):
            print(f"020: cannot find envp loop in {path}")
            return

    replacement = _HIDE_BLOCK + r"\1\n\tlen += strlen(envp[i]) + 1;"

    new_content = pattern.sub(replacement, content)

    if new_content == content:
        print(f"020: patch failed for {path}")
        return

    save(path, new_content)
    print(f"020: patched {path}")


if __name__ == "__main__":
    # Accept 1 or 2 arguments:
    #   python script.py                    -> use default lib/kobject.c
    #   python script.py lib/kobject.c    -> use provided path
    if len(sys.argv) > 2:
        target = sys.argv[1]  # Custom first arg after script name
        print(f"020: using provided path: {target}")
        patch_kobject_uevent(target)
    elif len(sys.argv) == 2:
        # Try as direct path
        target = sys.argv[1]
        patch_kobject_uevent(target)
    else:
        # Default: check common locations
        default_paths = [
            "lib/kobject.c",
            "common/lib/kobject.c",
            "kernel_platform/common/lib/kobject.c",
        ]
        found = False
        for p in default_paths:
            if os.path.exists(p):
                print(f"020: using default: {p}")
                patch_kobject_uevent(p)
                found = True
                break
        if not found:
            print(f"Usage: {sys.argv[0]} [lib/kobject.c]")
            sys.exit(1)