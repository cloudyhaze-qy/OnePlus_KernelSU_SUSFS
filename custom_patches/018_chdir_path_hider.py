#!/usr/bin/env python3
"""Hide su/ksud/magisk directory paths from chdir for app UIDs via fs/namei.c.

chdir(2) resolves the target path through __sys_chdir() or ksys_chdir()
which calls user_path_at() / user_path_dir(), entirely bypassing do_faccessat,
vfs_statx, do_readlinkat, and do_open_execat.

None of patches 006/014/015/016/017 intercept this path.
Probe [26] confirms two leaks (both returning EACCES):

  /data/adb/ksu     - EACCES (directory exists)
  /data/adb/magisk  - EACCES (directory exists)

Fix: intercept at the very start of the chdir implementation function, before
user_path_dir() is called.  filename is a __user pointer so strncpy_from_user
is used.  For matching paths with app UID >= 10000, return -ENOENT.

Patches:
  fs/namei.c  (__sys_chdir or ksys_chdir, depending on tree)
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


def _try_patterns(content):
    """Return the first matching regex match from all known chdir function patterns.

    Tries in order:
      1-3. int __sys_chdir(...)  {  (exact / single-line / multi-line args)
      4-6. int ksys_chdir(...)   {  (older / some OEM 5.10 trees)
      7-8. SYSCALL_DEFINE1(chdir, ...) { (no wrapper, syscall body directly)
    """
    patterns = [
        # __sys_chdir (standard upstream / GKI)
        re.compile(r"(int __sys_chdir\(const char __user \*filename\)\n\{)\n"),
        re.compile(r"(int __sys_chdir\([^\n)]+\)\n\{)\n"),
        re.compile(r"(int __sys_chdir\([^{]+?\n\{)\n", re.DOTALL),
        # ksys_chdir (older kernel / some OEM trees that did not rename)
        re.compile(r"(int ksys_chdir\(const char __user \*filename\)\n\{)\n"),
        re.compile(r"(int ksys_chdir\([^\n)]+\)\n\{)\n"),
        re.compile(r"(int ksys_chdir\([^{]+?\n\{)\n", re.DOTALL),
        # SYSCALL_DEFINE1 inlined (no separate wrapper function)
        re.compile(r"(SYSCALL_DEFINE1\(chdir, const char __user \*, filename\)\n\{)\n"),
        re.compile(r"(SYSCALL_DEFINE1\(chdir,[^{]+?\n\{)\n", re.DOTALL),
    ]
    for p in patterns:
        m = p.search(content)
        if m:
            return m
    return None


def patch_namei(path):
    content = load(path)

    if GUARD in content:
        print(f"018: {path} already patched, skipping")
        return

    m = _try_patterns(content)

    if not m:
        print(
            f"ERROR: anchor for __sys_chdir not found in {path}\n"
            "  Tried: __sys_chdir / ksys_chdir / SYSCALL_DEFINE1(chdir, ...)\n"
            "  Lines containing 'chdir' in the file:",
            file=sys.stderr,
        )
        for i, line in enumerate(content.splitlines(), 1):
            if "chdir" in line.lower():
                print(f"  L{i}: {line}", file=sys.stderr)
        sys.exit(1)

    # Insert _FILTER_BLOCK right after the opening brace + newline.
    # m.end() points just past the '\n' that follows '{'.
    insert_pos = m.end()
    new_content = content[:insert_pos] + _FILTER_BLOCK + content[insert_pos:]
    save(path, new_content)
    print(f"018: {path} (__sys_chdir/ksys_chdir) patched successfully")


if __name__ == "__main__":
    patch_namei("fs/namei.c")
