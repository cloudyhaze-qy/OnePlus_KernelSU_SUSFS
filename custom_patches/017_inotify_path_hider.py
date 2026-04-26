#!/usr/bin/env python3
"""Hide su/ksud/magisk paths from inotify_add_watch for app UIDs.

inotify_add_watch(2) resolves the watched path through its own kernel code
path entirely independent of do_faccessat / vfs_statx / do_readlinkat /
do_open_execat:

  sys_inotify_add_watch
   └─ inotify_add_watch()        ← fs/notify/inotify/inotify_user.c
       └─ inotify_find_inode()
           └─ kern_path()
               └─ filename_lookup / path_lookupat

None of patches 006/014/015/016 intercept this path.
Probe [27] confirms four leaks (all returning EACCES):

  /system/bin/su          – EACCES
  /data/adb/ksud          – EACCES
  /data/adb/ksu/bin/ksud  – EACCES
  /data/adb/ksu           – EACCES
  /data/adb/magisk        – EACCES

Fix: intercept inotify_add_watch() at its very start, before inotify_find_inode()
is called.  The pathname parameter is still a __user pointer at this stage, so
strncpy_from_user() is used to pull it into a kernel buffer.  For matching
paths with app UID >= 10000, return -ENOENT immediately.

Patches:
  fs/notify/inotify/inotify_user.c  (inotify_add_watch / SYSCALL_DEFINE3)
"""

import re
import sys

GUARD = "/* Hide su/ksud/magisk inotify paths from app UIDs (uid >= 10000) */"

# Injected at the very start of the inotify_add_watch syscall body, before
# any fd lookup or inode resolution.
# pathname is const char __user * — strncpy_from_user required.
# Variable declarations at block start for C89 compat.
_FILTER_BLOCK = '''\
\t{GUARD}
\tif (current_uid().val >= 10000 && pathname) {{
\t\tstatic const char * const __infy_su_paths[] = {{
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
\t\tchar __infy_buf[128];
\t\tlong __infy_n;
\t\tint __infy_i;
\t\t__infy_n = strncpy_from_user(__infy_buf, pathname,
\t\t\t\t\t     sizeof(__infy_buf) - 1);
\t\tif (__infy_n > 0) {{
\t\t\t__infy_buf[__infy_n] = \'\\0\';
\t\t\tfor (__infy_i = 0;
\t\t\t     __infy_i < ARRAY_SIZE(__infy_su_paths);
\t\t\t     __infy_i++) {{
\t\t\t\tif (!strcmp(__infy_buf, __infy_su_paths[__infy_i]))
\t\t\t\t\treturn -ENOENT;
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


# ── patch: fs/notify/inotify/inotify_user.c → inotify_add_watch ──────────────

def patch_inotify(path):
    """Inject su/ksud path filter at the start of inotify_add_watch().

    In Linux 5.10, the syscall entry looks like:

        SYSCALL_DEFINE3(inotify_add_watch, int, fd, const char __user *, pathname,
                        u32, mask)
        {
                struct fsnotify_mark *fsn_mark = NULL;
                ...

    We insert the filter block right after the opening brace so the check
    fires before any fd/inode resolution.
    """

    content = load(path)

    if GUARD in content:
        print(f"017: {path} already patched, skipping")
        return

    # ── Primary anchor: SYSCALL_DEFINE3(inotify_add_watch, ...) ──────────────
    # The macro definition may span multiple lines; match the opening brace
    # and the first local variable declaration.
    pattern = re.compile(
        r"(SYSCALL_DEFINE3\(inotify_add_watch,[^\)]+\)\n"
        r"\{)\n"
        r"([ \t]*struct fsnotify_mark \*fsn_mark)"
    )

    m = pattern.search(content)
    if not m:
        # ── Fallback: some trees use struct inotify_inode_mark as first var ──
        pattern2 = re.compile(
            r"(SYSCALL_DEFINE3\(inotify_add_watch,[^\)]+\)\n"
            r"\{)\n"
            r"([ \t]*(?:struct|int|unsigned|u32)\b)"
        )
        m = pattern2.search(content)

    if not m:
        # ── Fallback 2: tree may wrap arguments differently ───────────────────
        pattern3 = re.compile(
            r"(SYSCALL_DEFINE3\(inotify_add_watch,[\s\S]*?\)\n"
            r"\{)\n"
            r"([ \t]*(?:struct|int|unsigned|u32)\b)"
        )
        m = pattern3.search(content)

    if not m:
        print(
            f"ERROR: anchor for inotify_add_watch not found in {path}\n"
            "  Expected:\n"
            "    SYSCALL_DEFINE3(inotify_add_watch, int, fd,\n"
            "                    const char __user *, pathname, u32, mask)\n"
            "    {\n"
            "            struct fsnotify_mark *fsn_mark = NULL;",
            file=sys.stderr,
        )
        sys.exit(1)

    # Insert _FILTER_BLOCK right after the opening brace + newline
    new_content = (
        content[: m.end(1)]
        + "\n"
        + _FILTER_BLOCK
        + content[m.end(1) + 1:]
    )

    save(path, new_content)
    print(f"017: {path} (inotify_add_watch) patched successfully")


# ── main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    patch_inotify("fs/notify/inotify/inotify_user.c")
