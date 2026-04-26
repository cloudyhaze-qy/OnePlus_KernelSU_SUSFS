#!/usr/bin/env python3
"""Hide su/ksud/magisk paths from readlinkat for app UIDs via fs/stat.c.

ACE Engine (libtersafe sub_2F03FC) calls readlinkat(SVC #226) directly to
detect su / KernelSU / Magisk paths by checking whether they exist or are
symlinks.  The check is NOT covered by patches 006 (access/stat) or 014
(execveat) because readlinkat goes through a separate call path:

  sys_readlinkat
   └─ do_readlinkat       ← fs/stat.c
       └─ user_path_at / kern_path
           └─ vfs_readlink

Probe [20] confirms three leaks (uid=2000 shell, so uid>=10000 paths would
be similarly exposed for the game):

  /data/adb/ksud          – EACCES (file exists, patch 006 misses ksud)
  /data/adb/ksu/bin/ksud  – EACCES (file exists)
  /data/adb/magisk        – EACCES (KSU compat dir exists)

Fix: intercept do_readlinkat() at entry, read pathname from userspace, and
return -ENOENT for known su/ksud/magisk paths when called by app UID ≥ 10000.

Patches:
  fs/stat.c  (do_readlinkat)
"""

import re
import sys

GUARD = "/* Hide su/ksud/magisk readlinkat paths from app UIDs (uid >= 10000) */"

# Injected at the very start of do_readlinkat(), before any path resolution.
# pathname is const char __user *, so strncpy_from_user() is required.
# Variable declarations placed at block start for C89 compatibility.
_FILTER_BLOCK = '''\
\t{GUARD}
\tif (current_uid().val >= 10000 && pathname) {{
\t\tstatic const char * const __rl_su_paths[] = {{
\t\t\t"/system/bin/su",
\t\t\t"/system/xbin/su",
\t\t\t"/sbin/su",
\t\t\t"/su/bin/su",
\t\t\t"/data/local/bin/su",
\t\t\t"/data/local/xbin/su",
\t\t\t"/data/local/tmp/su",
\t\t\t"/data/adb/ksud",
\t\t\t"/data/adb/ksu/bin/ksud",
\t\t\t"/sbin/.magisk",
\t\t\t"/data/adb/magisk",
\t\t}};
\t\tchar __rl_buf[128];
\t\tlong __rl_n;
\t\tint __rl_i;
\t\t__rl_n = strncpy_from_user(__rl_buf, pathname,
\t\t\t\t\t   sizeof(__rl_buf) - 1);
\t\tif (__rl_n > 0) {{
\t\t\t__rl_buf[__rl_n] = \'\\0\';
\t\t\tfor (__rl_i = 0;
\t\t\t     __rl_i < ARRAY_SIZE(__rl_su_paths);
\t\t\t     __rl_i++) {{
\t\t\t\tif (!strcmp(__rl_buf, __rl_su_paths[__rl_i]))
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


# ── patch: fs/stat.c → do_readlinkat ─────────────────────────────────────────

def patch_stat(path):
    """Inject su/ksud/magisk path filter at the very start of do_readlinkat().

    In Linux 5.10, do_readlinkat begins with:

        static int do_readlinkat(int dfd, const char __user *pathname,
                                 char __user *buf, int bufsiz)
        {
            struct path path;
            int error;
            int empty = 0;
            unsigned int lookup_flags = LOOKUP_EMPTY;

    We insert the filter immediately after the opening brace so the check
    fires before any path resolution.
    """

    content = load(path)

    if GUARD in content:
        print(f"015: {path} already patched, skipping")
        return

    # ── Primary anchor: standard 5.10 do_readlinkat signature ────────────────
    pattern = re.compile(
        r"(static int do_readlinkat\("
        r"int dfd, const char __user \*pathname,\s*"
        r"char __user \*buf, int bufsiz\)\n"
        r"\{)\n"
        r"([ \t]*struct path path;)"
    )

    m = pattern.search(content)
    if not m:
        # ── Fallback: some trees use slightly different formatting ─────────────
        pattern2 = re.compile(
            r"(static int do_readlinkat\([^)]+\)\n"
            r"\{)\n"
            r"([ \t]*struct path path;)"
        )
        m = pattern2.search(content)

    if not m:
        print(
            f"ERROR: anchor for do_readlinkat not found in {path}",
            file=sys.stderr,
        )
        sys.exit(1)

    # Insert right after the opening brace line
    new_content = (
        content[: m.end(1)]
        + "\n"
        + _FILTER_BLOCK
        + content[m.end(1) + 1 :]
    )

    save(path, new_content)
    print(f"015: {path} (do_readlinkat) patched successfully")


# ── main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    patch_stat("fs/stat.c")
