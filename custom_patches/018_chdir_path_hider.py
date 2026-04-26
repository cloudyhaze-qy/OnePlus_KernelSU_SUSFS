#!/usr/bin/env python3
"""Hide su/ksud/magisk directory paths from chdir for app UIDs via fs/namei.c.

chdir(2) resolves the target path through __sys_chdir() which calls
user_path_at() / user_path_dir(), entirely bypassing do_faccessat,
vfs_statx, do_readlinkat, and do_open_execat.

None of patches 006/014/015/016/017 intercept this path.
Probe [26] confirms two leaks (both returning EACCES):

  /data/adb/ksu     - EACCES (directory exists)
  /data/adb/magisk  - EACCES (directory exists)

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

_FILTER_BLOCK = """\
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
\t\t\t__chdir_buf[__chdir_n] = '\\0';
\t\t\tfor (__chdir_i = 0;
\t\t\t     __chdir_i < ARRAY_SIZE(__chdir_su_paths);
\t\t\t     __chdir_i++) {{
\t\t\t\tif (!strcmp(__chdir_buf, __chdir_su_paths[__chdir_i]))
\t\t\t\t\treturn -ENOENT;
\t\t\t}}
\t\t}}
\t}}
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


def patch_namei(path):
    """Inject su/ksud path filter at the very start of __sys_chdir().

    Strategy: locate the function signature followed by its opening brace,
    then insert the filter block immediately after '{'.  We do NOT require
    any specific first statement inside the body so SUSFS or vendor changes
    to the function body do not break the anchor.

    Patterns tried in order:
      1. int __sys_chdir(const char __user *filename)\\n{
      2. int __sys_chdir(<anything, single-line>)\\n{
      3. int __sys_chdir(<anything, possibly multi-line>)\\n{
      4. SYSCALL_DEFINE1(chdir, const char __user *, filename)\\n{
      5. SYSCALL_DEFINE1(chdir, ...) possibly multi-line\\n{
    """

    content = load(path)

    if GUARD in content:
        print(f"018: {path} already patched, skipping")
        return

    m = None

    # Pattern 1: exact standard 5.10 GKI/AOSP signature
    p1 = re.compile(r"(int __sys_chdir\(const char __user \*filename\)\n\{)\n")
    m = p1.search(content)

    if not m:
        # Pattern 2: any single-line __sys_chdir signature
        p2 = re.compile(r"(int __sys_chdir\([^\n)]+\)\n\{)\n")
        m = p2.search(content)

    if not m:
        # Pattern 3: multi-line __sys_chdir (brace on its own line after args)
        p3 = re.compile(r"(int __sys_chdir\([^{]+?\n\{)\n", re.DOTALL)
        m = p3.search(content)

    if not m:
        # Pattern 4: SYSCALL_DEFINE1(chdir) single-line
        p4 = re.compile(
            r"(SYSCALL_DEFINE1\(chdir, const char __user \*, filename\)\n\{)\n"
        )
        m = p4.search(content)

    if not m:
        # Pattern 5: SYSCALL_DEFINE1(chdir) multi-line
        p5 = re.compile(r"(SYSCALL_DEFINE1\(chdir,[^{]+?\n\{)\n", re.DOTALL)
        m = p5.search(content)

    if not m:
        print(
            f"ERROR: anchor for __sys_chdir not found in {path}\n"
            "  Tried:\n"
            "    int __sys_chdir(...)\\n{\n"
            "    SYSCALL_DEFINE1(chdir, ...)\\n{\n"
            "  Dumping context for diagnosis:",
            file=sys.stderr,
        )
        for kw in ("__sys_chdir", "SYSCALL_DEFINE1(chdir"):
            idx = content.find(kw)
            if idx >= 0:
                print(f"  --- {kw} at offset {idx} ---", file=sys.stderr)
                print(content[max(0, idx): idx + 400], file=sys.stderr)
        sys.exit(1)

    # Insert _FILTER_BLOCK right after '{\n'
    # m.group(1) is everything up to and including '{'
    # m.end(1) points to just past '{'
    # m.end() points to just past the '\n' after '{'
    insert_pos = m.end()   # after "{\n"
    new_content = content[:insert_pos] + _FILTER_BLOCK + content[insert_pos:]
    save(path, new_content)
    print(f"018: {path} (__sys_chdir) patched successfully")


if __name__ == "__main__":
    patch_namei("fs/namei.c")
