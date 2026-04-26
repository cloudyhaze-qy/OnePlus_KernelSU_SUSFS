#!/usr/bin/env python3
"""Hide RT Dev KPM char device node (major=451) from getdents64 for app UIDs.

patch 010 blocks stat() (vfs_statx) and patch 012 blocks open() (chrdev_open).
However, the directory entry itself is still visible via getdents64/readdir.

ACE / libturinggame.so uses a dev_Sch()-style scan:
  1. opendir("/dev/")  → iterate_dir
  2. readdir()         → getdents64 → sees the 6-char random name entry
  3. stat(path)        → blocked by patch 010 (ENOENT)
  4. open(path)        → blocked by patch 012 (ENOENT)

Even with patches 010+012, the mystery entry name is still visible in
readdir output.  A sufficiently careful ACE build could infer RT Dev
presence purely from a 6-char mixed-case alphanumeric name in /dev/
(without relying on stat/open success).  Patch 013 closes that leak.

Injection point: fs/dcache.c → dcache_readdir()
  Wrap the dir_emit() call in a guard that skips entries whose inode
  is a char device with major=451 when called from app UID (≥ 10000).

At this point in dcache_readdir(), dentry->d_lock is NOT held
(spin_unlock was just called), so it is safe to read d_inode fields.
After the wrapped block, spin_lock() + move_cursor() execute normally
regardless of whether dir_emit was called, so cursor/position tracking
is unaffected.

Patches:
  fs/dcache.c  (dcache_readdir)
"""

import re
import sys

GUARD = "/* Hide RT Dev char device (major=451) from getdents64 for app UIDs (uid >= 10000) */"


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


# ── patch: fs/dcache.c → dcache_readdir ──────────────────────────────────────

def patch_dcache(path):
    """Wrap the dir_emit() call inside dcache_readdir() so that char device
    entries with major=451 are skipped for app UIDs (uid >= 10000).

    In Linux 5.10, the relevant section of dcache_readdir's while-loop is:

        spin_unlock(&dentry->d_lock);
        if (!dir_emit(ctx, next->d_name.name, next->d_name.len,
                      d_inode(next)->i_ino, dt_type(d_inode(next))))
            break;
        spin_lock(&dentry->d_lock);
        move_cursor(cursor, p);

    We wrap the dir_emit block so hidden entries fall through to the
    spin_lock + move_cursor, keeping cursor tracking correct.
    """

    content = load(path)

    if GUARD in content:
        print(f"013: {path} already patched, skipping")
        return

    # ── Primary pattern: 2-line dir_emit (most common in 5.10 GKI) ──────────
    # Capture:
    #   group(1) = leading whitespace (indent prefix for the loop body)
    #   group(2) = "spin_unlock(&dentry->d_lock);\n"
    #   group(3) = the full "if (!dir_emit(...))\n\t\tbreak;" block
    pattern2 = re.compile(
        r"([ \t]+)(spin_unlock\(&dentry->d_lock\);\n)"
        r"([ \t]+if \(!dir_emit\(ctx, next->d_name\.name, next->d_name\.len,\n"
        r"[ \t]+d_inode\(next\)->i_ino, dt_type\(d_inode\(next\)\)\)\)\n"
        r"[ \t]+break;)"
    )

    m = pattern2.search(content)
    if m:
        _apply_wrap(content, m, path, "2-line dir_emit")
        return

    # ── Fallback pattern: 1-line dir_emit ────────────────────────────────────
    pattern1 = re.compile(
        r"([ \t]+)(spin_unlock\(&dentry->d_lock\);\n)"
        r"([ \t]+if \(!dir_emit\(ctx, next->d_name\.name, next->d_name\.len,"
        r" d_inode\(next\)->i_ino, dt_type\(d_inode\(next\)\)\)\)\n"
        r"[ \t]+break;)"
    )

    m = pattern1.search(content)
    if m:
        _apply_wrap(content, m, path, "1-line dir_emit")
        return

    print(
        f"ERROR: anchor for dcache_readdir dir_emit not found in {path}\n"
        "  Expected pattern around:\n"
        "    spin_unlock(&dentry->d_lock);\n"
        "    if (!dir_emit(ctx, next->d_name.name, next->d_name.len,\n"
        "                  d_inode(next)->i_ino, dt_type(d_inode(next))))\n"
        "        break;",
        file=sys.stderr,
    )
    sys.exit(1)


def _apply_wrap(content, m, path, variant):
    """Given a regex match, wrap the dir_emit block and save."""
    indent = m.group(1)          # e.g. "\t\t"
    spin_line = indent + m.group(2)   # "spin_unlock(...)\n"
    dir_emit_block = m.group(3)  # "if (!dir_emit(...))\n\t\t\tbreak;"

    # Add one extra tab to every line of the dir_emit block
    indented_block = re.sub(r"^", "\t", dir_emit_block, flags=re.MULTILINE)

    new_code = (
        spin_line
        + indent + GUARD + "\n"
        + indent + "if (!(current_uid().val >= 10000 &&\n"
        + indent + "      S_ISCHR(d_inode(next)->i_mode) &&\n"
        + indent + "      MAJOR(d_inode(next)->i_rdev) == 451)) {\n"
        + indented_block + "\n"
        + indent + "}"
    )

    new_content = content[: m.start()] + new_code + content[m.end() :]
    save(path, new_content)
    print(f"013: {path} (dcache_readdir, {variant}) patched successfully")


# ── main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    patch_dcache("fs/dcache.c")
