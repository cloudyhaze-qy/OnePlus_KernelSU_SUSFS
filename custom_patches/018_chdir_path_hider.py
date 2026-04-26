#!/usr/bin/env python3
"""Hide su/ksud/magisk directory paths from chdir for app UIDs via fs/namei.c.

chdir(2) resolves the target path through __sys_chdir() which calls
user_path_at() / user_path_dir(), entirely bypassing do_faccessat,
vfs_statx, do_readlinkat, and do_open_execat:

  sys_chdir
   └─ __sys_chdir()              ← fs/namei.c
       └─ user_path_dir()
           └─ kern_path / path_lookupat

None of patches 006/014/015/016/017 intercept this path.
Probe [26] confirms two leaks (both returning EACCES):

  /data/adb/ksu     – EACCES (directory exists)
  /data/adb/magisk  – EACCES (directory exists)

Fix: intercept __sys_chdir() at its very start, before user_path_dir() is
called.  The filename parameter is a __user pointer, so strncpy_from_user()
is used to read it into a kernel buffer.  For matching paths with app
UID >= 10000, return -ENOENT immediately.

Patches:
  fs/namei.c  (__sys_chdir)
"""

import re
import sys

GUARD = "/* Hide su/ksud/magisk chdir paths from app UIDs (uid >= 10000) */"

# Injected at the very start of __sys_chdir(), before any path resolution.
# filename is const char __user * — strncpy_from_user required.
# Variable declarations at block start for C89 compat.
_FILTER_BLOCK = '''\
\t{GUARD}
\tif (current_uid().val >= 10000 && filename) {{
\t\tstatic const char * const __chdir_su_paths[] = {{
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
\t\tchar __chdir_buf[128];
\t\tlong __chdir_n;
\t\tint __chdir_i;
\t\t__chdir_n = strncpy_from_user(__chdir_buf, filename,
\t\t\t\t\t     sizeof(__chdir_buf) - 1);
\t\tif (__chdir_n > 0) {{
\t\t\t__chdir_buf[__chdir_n] = \'\\0\';
\t\t\tfor (__chdir_i = 0;
\t\t\t     __chdir_i < ARRAY_SIZE(__chdir_su_paths);
\t\t\t     __chdir_i++) {{
\t\t\t\tif (!strcmp(__chdir_buf, __chdir_su_paths[__chdir_i]))
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


# ── patch: fs/namei.c → __sys_chdir ──────────────────────────────────────────

def patch_namei(path):
    """Inject su/ksud path filter at the very start of __sys_chdir().

    In Linux 5.10+, the function looks like:

        int __sys_chdir(const char __user *filename)
        {
                struct path path;
                int error;
                unsigned int lookup_flags = LOOKUP_FOLLOW | LOOKUP_DIRECTORY;
        retry:
                error = user_path_at(AT_FDCWD, filename, lookup_flags, &path);

    We insert the filter block right after the opening brace so the check
    fires before any VFS path resolution begins.

    Fallback: Some 5.10 vendor trees may still have SYSCALL_DEFINE1(chdir, ...)
    without a separate __sys_chdir wrapper.  The fallback targets the macro
    body in that case.
    """

    content = load(path)

    if GUARD in content:
        print(f"018: {path} already patched, skipping")
        return

    # ── Primary anchor: __sys_chdir with const char __user * ─────────────────
    pattern = re.compile(
        r"(int __sys_chdir\(const char __user \*filename\)\n"
        r"\{)\n"
        r"([ \t]*struct path path;)"
    )

    m = pattern.search(content)
    if not m:
        # ── Fallback 1: __user qualifier on different position ────────────────
        pattern2 = re.compile(
            r"(int __sys_chdir\([^)]+\)\n"
            r"\{)\n"
            r"([ \t]*struct path path;)"
        )
        m = pattern2.search(content)

    if not m:
        # ── Fallback 2: SYSCALL_DEFINE1 without __sys_chdir wrapper ──────────
        pattern3 = re.compile(
            r"(SYSCALL_DEFINE1\(chdir, const char __user \*, filename\)\n"
            r"\{)\n"
            r"([ \t]*struct path path;)"
        )
        m = pattern3.search(content)

    if not m:
        # ── Fallback 3: SYSCALL_DEFINE1 multiline ────────────────────────────
        pattern4 = re.compile(
            r"(SYSCALL_DEFINE1\(chdir,[\s\S]*?\)\n"
            r"\{)\n"
            r"([ \t]*struct path path;)"
        )
        m = pattern4.search(content)

    if not m:
        print(
            f"ERROR: anchor for __sys_chdir not found in {path}\n"
            "  Expected one of:\n"
            "    int __sys_chdir(const char __user *filename)\n"
            "    {\n"
            "            struct path path;\n"
            "  or:\n"
            "    SYSCALL_DEFINE1(chdir, const char __user *, filename)\n"
            "    {\n"
            "            struct path path;",
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
    print(f"018: {path} (__sys_chdir) patched successfully")


# ── main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    patch_namei("fs/namei.c")
