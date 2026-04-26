#!/usr/bin/env python3
"""Hide RT Dev KPM char device node (major=451) from app UIDs via vfs_statx.

RT Dev KPM registers a misc character device with major number 451 and
creates a node in /dev/ with a random 6-character alphanumeric name
(e.g., /dev/qQ5zPd). The node has these properties:
  - uid=0, gid=0, mode=0600, type=DT_CHR, major=451

ACE / libturinggame.so uses a dev_Sch()-style scan:
  1. opendir("/dev/") → iterate entries via readdir()
  2. for each entry: stat() to check uid/gid/mode/type
  3. if stat passes all filters → open(fd) + ioctl to confirm RT Dev present

The entire scan depends on stat() succeeding.  Returning ENOENT from
vfs_statx() for major=451 char devices when called by uid >= 10000
causes dev_Sch() to execute `if (stat(...) < 0) continue` and skip the
entry unconditionally.

All stat-family syscalls funnel through vfs_statx() in Linux 5.10:
  sys_stat / sys_lstat / sys_fstatat / sys_statx
  → vfs_stat / vfs_lstat / vfs_fstatat / vfs_statx (all reach vfs_statx)
  → vfs_getattr → fills kstat

We inject the MAJOR check immediately after vfs_getattr fills the kstat
but before path_put, so no resources are leaked.

Patches:
  fs/stat.c  (vfs_statx)
"""

import re
import sys

GUARD = "/* Hide RT Dev char device node (major=451) from app UIDs (uid >= 10000) */"

# Injected right after vfs_getattr fills stat, before path_put.
_HIDE_BLOCK = """\
\t{GUARD}
\tif (!error && current_uid().val >= 10000 &&
\t    S_ISCHR(stat->mode) && MAJOR(stat->rdev) == 451)
\t\terror = -ENOENT;
""".format(GUARD=GUARD)

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


# ── patch: fs/stat.c → vfs_statx ─────────────────────────────────────────────

def patch_stat(path):
    """Insert major=451 hide block in vfs_statx(), between vfs_getattr()
    and path_put().

    In Linux 5.10 (OnePlus sm8475) the relevant section of vfs_statx is:

        error = vfs_getattr(&path, stat, request_mask, flags);
        path_put(&path);
        if (retry_estale(error, lookup_flags)) {

    We insert between the first two lines so the check fires once per
    lookup (the goto-retry loop re-enters above user_path_at, not here).
    """

    content = load(path)

    if GUARD in content:
        print(f"010: {path} already patched, skipping")
        return

    # Anchor: vfs_getattr call followed (possibly with SUSFS lines in between)
    # by path_put(&path) in vfs_statx.
    #
    # In unpatched Linux 5.10:
    #   error = vfs_getattr(&path, stat, request_mask, flags);
    #   path_put(&path);
    #
    # After SUSFS patches fs/stat.c (susfs_sus_kstat hook):
    #   error = vfs_getattr(&path, stat, request_mask, flags);
    #   #ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
    #   	if (!error)
    #   		susfs_sus_kstat(&path, stat);
    #   #endif
    #   path_put(&path);
    #
    # Use `(?:[^\n]*\n)*?` (any lines, lazy) so we skip the SUSFS block
    # regardless of whether its lines start with a tab or not (#ifdef/#endif).
    pattern = re.compile(
        r"(\terror = vfs_getattr\(&path, stat, request_mask, flags\);\n"
        r"(?:[^\n]*\n)*?)"
        r"(\tpath_put\(&path\);)"
    )

    m = pattern.search(content)
    if not m:
        print(
            f"ERROR: anchor for vfs_statx not found in {path}\n"
            "  Expected:\n"
            "    error = vfs_getattr(&path, stat, request_mask, flags);\n"
            "    path_put(&path);",
            file=sys.stderr,
        )
        sys.exit(1)

    insert_pos = m.end(1)  # right after the vfs_getattr line
    new_content = content[:insert_pos] + _HIDE_BLOCK + content[insert_pos:]

    save(path, new_content)
    print(f"010: {path} (vfs_statx) patched successfully")


# ── main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    patch_stat("fs/stat.c")
