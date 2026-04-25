#!/usr/bin/env python3
"""Hide su/root binary paths from app UIDs via fs/open.c and fs/stat.c.

When a process with UID >= 10000 (Android app) calls access() or stat()
on well-known su binary paths, return ENOENT so the file appears absent.

This hides /system/bin/su (and other root binary paths) that are baked
into stock ROMs from anti-cheat libraries that do root detection via:
  access("/system/bin/su", F_OK)
  stat("/system/bin/su", &st)
  open("/system/bin/su", ...)

Patches:
  fs/open.c   (do_faccessat  – covers access() syscall)
  fs/stat.c   (vfs_statx     – covers stat/lstat/fstatat/statx syscalls)
"""

import re
import sys

GUARD = "/* Hide su/root binary paths from app UIDs (uid >= 10000) */"

# ── shared filter logic ─────────────────────────────────────────────────────

# Inline C block inserted at the start of both patched functions.
# Uses strncpy_from_user to read the userspace filename, then strcmp-matches
# against the su denylist.  Returns -ENOENT on match for app UIDs.
_FILTER_BLOCK = '''\
\t{GUARD}
\tif (current_uid().val >= 10000) {{
\t\tstatic const char * const __su_paths[] = {{
\t\t\t"/system/bin/su",
\t\t\t"/system/xbin/su",
\t\t\t"/sbin/su",
\t\t\t"/su/bin/su",
\t\t\t"/data/local/bin/su",
\t\t\t"/data/local/xbin/su",
\t\t\t"/data/local/tmp/su",
\t\t}};
\t\tchar __su_buf[96];
\t\tlong __su_n = strncpy_from_user(__su_buf, filename,
\t\t\t\t\t\tsizeof(__su_buf) - 1);
\t\tif (__su_n > 0) {{
\t\t\tint __su_i;
\t\t\t__su_buf[__su_n] = \'\\0\';
\t\t\tfor (__su_i = 0;
\t\t\t     __su_i < ARRAY_SIZE(__su_paths);
\t\t\t     __su_i++) {{
\t\t\t\tif (!strcmp(__su_buf, __su_paths[__su_i]))
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


# ── patch 1: fs/open.c → do_faccessat ───────────────────────────────────────

def patch_namei(path):
    """Insert su-path filter into do_faccessat() right after the flags
    validation block, before the retry:/filename_lookup label."""

    content = load(path)

    if GUARD in content:
        print(f"006: {path} already patched, skipping")
        return

    # Anchor: the AT_SYMLINK_NOFOLLOW / AT_EMPTY_PATH flags check that
    # immediately precedes the lookup_flags adjustments inside do_faccessat.
    #
    # Pattern (flags check -> optional blank line -> lookup_flags tweak):
    #   if (flags & ~(AT_EACCESS | AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH))
    #       return -EINVAL;
    #
    # followed by one of:
    #   \tif (flags & AT_SYMLINK_NOFOLLOW)
    # OR
    #   \tif (flags & AT_EMPTY_PATH)
    # OR
    #   \tretry:
    pattern = re.compile(
        r"([ \t]*if \(flags & ~\(AT_EACCESS \| AT_SYMLINK_NOFOLLOW"
        r" \| AT_EMPTY_PATH\)\)\n"
        r"[ \t]*return -EINVAL;\n)"
        r"(\n?[ \t]*(?:if \(flags & AT_|retry:))"
    )

    m = pattern.search(content)
    if not m:
        # Fallback anchor: simpler two-argument do_faccessat variant used
        # in some 5.10 trees that only accept (dfd, filename, mode).
        pattern = re.compile(
            r"([ \t]*if \(mode & ~S_IRWXO\)[^\n]*\n"
            r"[ \t]*return -EINVAL;\n)"
            r"(\n?[ \t]*(?:retry:|unsigned int|struct filename))"
        )
        m = pattern.search(content)

    if not m:
        print(
            f"ERROR: anchor for do_faccessat not found in {path}",
            file=sys.stderr,
        )
        sys.exit(1)

    insert_pos = m.end(1)
    new_content = content[:insert_pos] + _FILTER_BLOCK + content[insert_pos:]

    save(path, new_content)
    print(f"006: {path} (do_faccessat) patched successfully")


# ── patch 2: fs/stat.c → vfs_statx ──────────────────────────────────────────

def patch_stat(path):
    """Insert su-path filter at the very start of vfs_statx(), before any
    path resolution, so stat()/lstat()/fstatat()/statx() are all covered."""

    content = load(path)

    if GUARD in content:
        print(f"006: {path} already patched, skipping")
        return

    # Anchor: vfs_statx function opening brace.
    # In Linux 5.10, vfs_statx has this signature:
    #   int vfs_statx(int dfd, const char __user *filename, int flags,
    #                 struct kstat *stat, u32 request_mask)
    #   {
    #       struct path path;
    #       int error = -EINVAL;
    pattern = re.compile(
        r"(int vfs_statx\(int dfd, const char __user \*filename,"
        r"[^{]+\{)\n"
        r"([ \t]*struct path path;)"
    )

    m = pattern.search(content)
    if not m:
        print(
            f"ERROR: anchor for vfs_statx not found in {path}",
            file=sys.stderr,
        )
        sys.exit(1)

    insert_pos = m.end(1) + 1  # right after the opening brace + newline
    new_content = (
        content[: m.end(1)]
        + "\n"
        + _FILTER_BLOCK
        + content[m.end(1) + 1 :]
    )

    save(path, new_content)
    print(f"006: {path} (vfs_statx) patched successfully")


# ── main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    patch_namei("fs/open.c")
    patch_stat("fs/stat.c")
