#!/usr/bin/env python3
"""Hide su/ksud/magisk paths from openat(O_PATH) for app UIDs via fs/open.c.

patch 006 patches do_faccessat (access()) and vfs_statx (stat()).
patch 014 patches do_open_execat (execveat/execve).
patch 015 patches do_readlinkat (readlinkat).
However, openat() — including the O_PATH flag variant — goes through a
completely separate code path that none of the above patches cover:

  sys_openat / sys_openat2
   └─ do_sys_openat2()          ← fs/open.c
       └─ getname(filename)     ← copies path to kernel struct filename
       └─ get_unused_fd_flags()
       └─ do_filp_open() / do_o_path_open()
           └─ vfs_open / open_last_lookups

Neither do_faccessat nor vfs_statx is invoked for an openat() call.
Probe [22] confirms four leaks (all returning EACCES — file exists but
/data/adb/ mode 700 blocks access):

  /data/adb/ksud          – EACCES
  /data/adb/ksu           – EACCES
  /data/adb/ksu/bin/ksud  – EACCES
  /data/adb/magisk        – EACCES

Fix: intercept do_sys_openat2() right after getname() succeeds.  At that
point, tmp->name is already a kernel-space copy of the path (no
strncpy_from_user needed).  For matching paths with app UID >= 10000, call
putname(tmp) to release the allocation and return -ENOENT directly.

This single insertion covers ALL openat() variants including O_PATH,
O_RDONLY, O_WRONLY, O_RDWR, etc.

Patches:
  fs/open.c  (do_sys_openat2)
"""

import re
import sys

GUARD = "/* Hide su/ksud/magisk openat paths from app UIDs via do_sys_openat2 (uid >= 10000) */"

# Injected right after:
#   tmp = getname(filename);
#   if (IS_ERR(tmp))
#       return PTR_ERR(tmp);
#
# At this point, tmp->name is the kernel-space copy of the path.
# We must call putname(tmp) before returning -ENOENT to free the allocation.
_FILTER_BLOCK = '''\
\t{GUARD}
\tif (current_uid().val >= 10000 && tmp && tmp->name) {{
\t\tstatic const char * const __openat_su_paths[] = {{
\t\t\t"/system/bin/su",
\t\t\t"/system/xbin/su",
\t\t\t"/sbin/su",
\t\t\t"/su/bin/su",
\t\t\t"/data/local/bin/su",
\t\t\t"/data/local/xbin/su",
\t\t\t"/data/local/tmp/su",
\t\t\t"/data/adb/ksud",
\t\t\t"/data/adb/ksu",
\t\t\t"/data/adb/ksu/bin/ksud",
\t\t\t"/data/adb/magisk",
\t\t\t"/sbin/.magisk",
\t\t}};
\t\tint __openat_i;
\t\tfor (__openat_i = 0;
\t\t     __openat_i < ARRAY_SIZE(__openat_su_paths);
\t\t     __openat_i++) {{
\t\t\tif (!strcmp(tmp->name, __openat_su_paths[__openat_i])) {{
\t\t\t\tputname(tmp);
\t\t\t\treturn -ENOENT;
\t\t\t}}
\t\t}}
\t}}
'''.format(GUARD=GUARD)

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


# ── patch: fs/open.c → do_sys_openat2 ────────────────────────────────────────

def patch_open(path):
    """Inject su/ksud path filter in do_sys_openat2() after getname() succeeds.

    In Linux 5.10, the relevant section of do_sys_openat2() looks like:

        tmp = getname(filename);
        if (IS_ERR(tmp))
            return PTR_ERR(tmp);

        fd = get_unused_fd_flags(how->flags);

    We insert the filter block between the IS_ERR check and
    get_unused_fd_flags so the path is checked before any fd allocation.
    """

    content = load(path)

    if GUARD in content:
        print(f"016: {path} already patched, skipping")
        return

    # ── Primary anchor: standard 5.10 do_sys_openat2 getname block ───────────
    # Match the getname + IS_ERR pattern, capturing everything up to and
    # including the closing "return PTR_ERR(tmp);" line, then a blank line
    # followed by the get_unused_fd_flags call.
    pattern = re.compile(
        r"([ \t]*tmp = getname\(filename\);\n"
        r"[ \t]*if \(IS_ERR\(tmp\)\)\n"
        r"[ \t]*return PTR_ERR\(tmp\);\n)"
        r"(\n?[ \t]*fd = get_unused_fd_flags\b)"
    )

    m = pattern.search(content)
    if not m:
        # ── Fallback: trees where get_unused_fd_flags is on same line ────────
        pattern2 = re.compile(
            r"([ \t]*tmp = getname\(filename\);\n"
            r"[ \t]*if \(IS_ERR\(tmp\)\)\n"
            r"[ \t]*return PTR_ERR\(tmp\);\n)"
            r"(\n?[ \t]*(?:fd|long)\s*=\s*get_unused_fd_flags\b)"
        )
        m = pattern2.search(content)

    if not m:
        print(
            f"ERROR: anchor for do_sys_openat2 not found in {path}\n"
            "  Expected:\n"
            "    tmp = getname(filename);\n"
            "    if (IS_ERR(tmp))\n"
            "        return PTR_ERR(tmp);\n"
            "\n"
            "    fd = get_unused_fd_flags(...);",
            file=sys.stderr,
        )
        sys.exit(1)

    # Insert _FILTER_BLOCK right after "return PTR_ERR(tmp);\n"
    new_content = (
        content[: m.end(1)]
        + _FILTER_BLOCK
        + content[m.end(1):]
    )

    save(path, new_content)
    print(f"016: {path} (do_sys_openat2) patched successfully")


# ── main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    patch_open("fs/open.c")
