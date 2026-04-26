#!/usr/bin/env python3
"""Hide RT Dev KPM char device node (major=451) from getdents64 for app UIDs.

patch 010 blocks stat() (vfs_statx) and patch 012 blocks open() (chrdev_open).
However, the directory entry itself is still visible via getdents64/readdir.

ACE / libturinggame.so uses a dev_Sch()-style scan:
  1. opendir("/dev/")  -> iterate_dir
  2. readdir()         -> getdents64 -> sees the 6-char random name entry
  3. stat(path)        -> blocked by patch 010 (ENOENT)
  4. open(path)        -> blocked by patch 012 (ENOENT)

Even with patches 010+012, the mystery entry name is still visible in
readdir output.  A sufficiently careful ACE build could infer RT Dev
presence purely from a 6-char mixed-case alphanumeric name in /dev/
(without relying on stat/open success).  Patch 013 closes that leak.

Injection point: fs/libfs.c (or fs/dcache.c) -> dcache_readdir()
  Wrap the dir_emit() call in a guard that skips entries whose inode
  is a char device with major=451 when called from app UID (>= 10000).

NOTE: SUSFS v2.x inserts its own path-hiding check between the
spin_unlock(&next->d_lock) and the dir_emit() call.  Therefore we do
NOT anchor on spin_unlock; we anchor directly on the dir_emit() line.

After the wrapped block, moved=true / cursor=next execute regardless,
so cursor/position tracking is unaffected when an entry is hidden.

Patches:
  fs/libfs.c  (standard 5.10 GKI/AOSP -- dcache_readdir)
  fs/dcache.c (older vendor trees -- fallback)
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


# -- patch: dcache_readdir dir_emit -------------------------------------------

def patch_dcache(path):
    """Wrap the dir_emit() call inside dcache_readdir().

    We anchor directly on the dir_emit() call (NOT on the preceding
    spin_unlock), because SUSFS v2.x inserts its own check between the
    two, so a spin_unlock+dir_emit adjacency no longer holds.

    Patterns cover all known 5.10 variants:

      Variant 1 (standard AOSP/GKI, 2-line, d_inode() accessor):
        if (!dir_emit(ctx, next->d_name.name, next->d_name.len,
                      d_inode(next)->i_ino, dt_type(d_inode(next))))
            break;

      Variant 2 (1-line, d_inode() accessor):
        if (!dir_emit(ctx, next->d_name.name, next->d_name.len, d_inode(next)->i_ino, dt_type(d_inode(next))))
            break;

      Variant 3 (2-line, direct member access):
        if (!dir_emit(ctx, next->d_name.name, next->d_name.len,
                      next->d_inode->i_ino, dt_type(next->d_inode)))
            break;

      Variant 4 (1-line, direct member access):
        if (!dir_emit(ctx, next->d_name.name, next->d_name.len, next->d_inode->i_ino, dt_type(next->d_inode)))
            break;

      Variant 5 (broad fallback):
        matches any dir_emit(ctx, next->d_name... followed by break;

    Each pattern captures 2 groups:
      group(1) = leading indent of the `if (!dir_emit` line
      group(2) = the complete if(!dir_emit...))\nbreak; block
    """

    content = load(path)

    if GUARD in content:
        print(f"013: {path} already patched, skipping")
        return

    # Variant 1: 2-line, d_inode() accessor (standard 5.10 GKI/AOSP)
    p1 = re.compile(
        r"(?m)^([ \t]+)(if \(!dir_emit\(ctx, next->d_name\.name, next->d_name\.len,\n"
        r"[ \t]+d_inode\(next\)->i_ino, dt_type\(d_inode\(next\)\)\)\)\n"
        r"[ \t]+break;)"
    )
    m = p1.search(content)
    if m:
        _apply_wrap(content, m, path, "2-line d_inode()")
        return

    # Variant 2: 1-line, d_inode() accessor
    p2 = re.compile(
        r"(?m)^([ \t]+)(if \(!dir_emit\(ctx, next->d_name\.name, next->d_name\.len,"
        r"[ \t]+d_inode\(next\)->i_ino, dt_type\(d_inode\(next\)\)\)\)\n"
        r"[ \t]+break;)"
    )
    m = p2.search(content)
    if m:
        _apply_wrap(content, m, path, "1-line d_inode()")
        return

    # Variant 3: 2-line, direct member access
    p3 = re.compile(
        r"(?m)^([ \t]+)(if \(!dir_emit\(ctx, next->d_name\.name, next->d_name\.len,\n"
        r"[ \t]+next->d_inode->i_ino, dt_type\(next->d_inode\)\)\)\n"
        r"[ \t]+break;)"
    )
    m = p3.search(content)
    if m:
        _apply_wrap(content, m, path, "2-line next->d_inode")
        return

    # Variant 4: 1-line, direct member access
    p4 = re.compile(
        r"(?m)^([ \t]+)(if \(!dir_emit\(ctx, next->d_name\.name, next->d_name\.len,"
        r"[ \t]+next->d_inode->i_ino, dt_type\(next->d_inode\)\)\)\n"
        r"[ \t]+break;)"
    )
    m = p4.search(content)
    if m:
        _apply_wrap(content, m, path, "1-line next->d_inode")
        return

    # Variant 5: broad fallback -- any dir_emit(ctx, next->d_name followed by break;
    p5 = re.compile(
        r"(?m)^([ \t]+)(if \(!dir_emit\(ctx, next->d_name\.name,[^\n]*\n"
        r"(?:[ \t]+[^\n]*\n)*?"
        r"[ \t]+break;)"
    )
    m = p5.search(content)
    if m:
        _apply_wrap(content, m, path, "broad next->d_name fallback")
        return

    print(
        f"ERROR: anchor for dcache_readdir dir_emit not found in {path}\n"
        "  Looked for all of:\n"
        "    if (!dir_emit(ctx, next->d_name.name, next->d_name.len,\n"
        "                  d_inode(next)->i_ino, ...))    [2-line d_inode()]\n"
        "    if (!dir_emit(ctx, next->d_name.name, next->d_name.len, ...))  [1-line]\n"
        "    if (!dir_emit(ctx, next->d_name.name, next->d_name.len,\n"
        "                  next->d_inode->i_ino, ...))    [2-line direct member]\n"
        "    if (!dir_emit(ctx, next->d_name.name, ...))  [broad fallback]\n"
        "  None matched. Dump of dcache_readdir area for diagnosis:",
        file=sys.stderr,
    )
    idx = content.find("dcache_readdir")
    if idx >= 0:
        snippet = content[max(0, idx): idx + 800]
        print(snippet, file=sys.stderr)
    sys.exit(1)


def _apply_wrap(content, m, path, variant):
    """Wrap the matched dir_emit block with a major-451 uid guard.

    Match structure:
      group(1) = leading indent (e.g. "\t\t")
      group(2) = the full if(!dir_emit...)\n...break; block
    """
    indent = m.group(1)          # e.g. "\t\t"
    dir_emit_block = m.group(2)  # "if (!dir_emit(...))\n...\t\t\tbreak;"

    # Add one extra tab to every line of the dir_emit block so it nests
    # inside the new guard `if` body.
    indented_block = re.sub(r"(?m)^", "\t", dir_emit_block)

    new_code = (
        indent + GUARD + "\n"
        + indent + "if (!(current_uid().val >= 10000 &&\n"
        + indent + "      S_ISCHR(d_inode(next)->i_mode) &&\n"
        + indent + "      MAJOR(d_inode(next)->i_rdev) == 451)) {\n"
        + indented_block + "\n"
        + indent + "}"
    )

    new_content = content[: m.start()] + new_code + content[m.end():]
    save(path, new_content)
    print(f"013: {path} (dcache_readdir, {variant}) patched successfully")


# -- main ---------------------------------------------------------------------

if __name__ == "__main__":
    # dcache_readdir lives in fs/libfs.c in standard 5.10 GKI/AOSP trees.
    # Some older vendor trees keep it in fs/dcache.c -- try both.
    import os
    if os.path.isfile("fs/libfs.c"):
        patch_dcache("fs/libfs.c")
    else:
        patch_dcache("fs/dcache.c")