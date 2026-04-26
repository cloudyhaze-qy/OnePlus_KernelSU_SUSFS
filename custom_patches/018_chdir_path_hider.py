#!/usr/bin/env python3
"""Hide su/ksud/magisk directory paths from chdir for app UIDs.

chdir(2) calls the kernel chdir implementation before any VFS permission
check completes, so patches 006/014/015/016/017 do not intercept it.
Probe [26] confirms two leaks (both EACCES = directory exists):
  /data/adb/ksu, /data/adb/magisk

Fix: inject a path filter at the very start of the chdir implementation
function (before user_path_dir is called).  filename is __user so we use
strncpy_from_user.  For matching paths with app UID >= 10000 return -ENOENT.

Candidate files searched (in order):
  fs/namei.c      -- upstream / GKI standard location
  kernel/sys.c    -- some older / vendor trees put it here
  fs/open.c       -- rare, but occasionally seen in OEM trees
"""

import os
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
    """Return the first matching regex match, covering all known chdir variants.

    Patterns (in priority order):
      1-3.  int __sys_chdir(...)  {   upstream / GKI
      4-6.  int ksys_chdir(...)   {   older / some OEM 5.10
      7-8.  SYSCALL_DEFINE1(chdir,...) {   no wrapper function
    """
    patterns = [
        # __sys_chdir (standard upstream / GKI)
        re.compile(r"(int __sys_chdir\(const char __user \*filename\)\n\{)\n"),
        re.compile(r"(int __sys_chdir\([^\n)]+\)\n\{)\n"),
        re.compile(r"(int __sys_chdir\([^{]+?\n\{)\n", re.DOTALL),
        # ksys_chdir (older kernel / OEM)
        re.compile(r"(int ksys_chdir\(const char __user \*filename\)\n\{)\n"),
        re.compile(r"(int ksys_chdir\([^\n)]+\)\n\{)\n"),
        re.compile(r"(int ksys_chdir\([^{]+?\n\{)\n", re.DOTALL),
        # SYSCALL_DEFINE1(chdir) inlined, no wrapper
        re.compile(r"(SYSCALL_DEFINE1\(chdir, const char __user \*, filename\)\n\{)\n"),
        re.compile(r"(SYSCALL_DEFINE1\(chdir,[^{]+?\n\{)\n", re.DOTALL),
    ]
    for p in patterns:
        m = p.search(content)
        if m:
            return m
    return None


def patch_file(path):
    """Try to patch the chdir implementation in `path`. Returns True on success."""
    if not os.path.isfile(path):
        return False

    content = load(path)

    if GUARD in content:
        print(f"018: {path} already patched, skipping")
        return True

    m = _try_patterns(content)
    if not m:
        return False

    insert_pos = m.end()
    new_content = content[:insert_pos] + _FILTER_BLOCK + content[insert_pos:]
    save(path, new_content)
    print(f"018: {path} (chdir impl) patched successfully")
    return True


def main():
    # Files to search, in order of likelihood
    candidates = [
        "fs/namei.c",
        "kernel/sys.c",
        "fs/open.c",
    ]

    for candidate in candidates:
        if patch_file(candidate):
            return

    # All candidates failed — dump diagnostics
    print(
        "ERROR: anchor for chdir not found in any candidate file\n"
        f"  Searched: {candidates}\n"
        "  Lines containing 'chdir' in each file:",
        file=sys.stderr,
    )
    for candidate in candidates:
        if not os.path.isfile(candidate):
            print(f"  {candidate}: FILE NOT FOUND", file=sys.stderr)
            continue
        content = load(candidate)
        hits = [(i + 1, ln) for i, ln in enumerate(content.splitlines())
                if "chdir" in ln.lower()]
        if hits:
            print(f"  --- {candidate} ---", file=sys.stderr)
            for lineno, ln in hits:
                print(f"    L{lineno}: {ln}", file=sys.stderr)
        else:
            print(f"  {candidate}: no 'chdir' found", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()
