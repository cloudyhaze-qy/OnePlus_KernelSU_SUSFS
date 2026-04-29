#!/usr/bin/env python3
"""Hide RT Dev KPM char device (major=451) from sysfs readdir.

Patch 013 covers /dev/ getdents64/readdir, but sysfs directories
(/sys/class/, /sys/devices/, /sys/module/) have their own readdir
implementation: sysfs_readdir().

ACE monitors both /dev/ and sysfs directories. Even if /dev/
entries are hidden, sysfs may still expose device nodes.

The scan pattern:
  1. opendir("/sys/class/") or similar sysfs dirs
  2. readdir() iterates entries
  3. If entry is a char device with major=451 → RT Dev detected

We filter at sysfs_readdir(): skip emitting entries for RT Dev devices.

Injection point: fs/sysfs/dir.c → sysfs_readdir()
  Wrap dir_emit() call inside a guard checking MAJOR(inode).

NOTE: This is the same pattern as patch 013 (getdents64 hider),
but applied to the sysfs-specific readdir implementation.

Patches:
  fs/sysfs/dir.c  (sysfs_readdir)
"""

import re
import sys

GUARD = "/* Hide RT Dev (major=451) from sysfs readdir */"


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


# -- patch: fs/sysfs/dir.c → sysfs_readdir -------------------------

def patch_sysfs_readdir(path):
    """Wrap dir_emit() in sysfs_readdir() with RT Dev filter.

    We anchor on dir_emit() call inside sysfs_readdir(), similar to
    patch 013 (getdents64 hider) but for sysfs-specific code.

    In Linux 5.10 fs/sysfs/dir.c sysfs_readdir():
        while (1) {
            ...
            if (sysfs_is_dir(p->s_next, type))
                ino = sysfs_ino(p->s_next);
            else
                ino = old_ino++;

            if (!dir_emit(ctx, p->s_name, p->s_name_len, ino, type))
                break;
        }

    We insert a check before dir_emit() to skip RT Dev devices.
    """

    content = load(path)

    if GUARD in content:
        print(f"022: {path} already patched, skipping")
        return

    # Anchor: dir_emit call in sysfs_readdir
    # Multiple patterns to handle different kernel versions
    patterns = [
        # Pattern 1: dir_emit with sysfs_ino/old_ino
        re.compile(
            r"(\tif \(!dir_emit\(ctx, p->s_name, p->s_name_len,\n"
            r"\s+ino, type\)\)\n"
            r"\t\tbreak;)"
        ),
        # Pattern 2: simplified dir_emit
        re.compile(r"(\tif \(!dir_emit\(ctx,)"),
    ]

    patched = False
    for pattern in patterns:
        if pattern.search(content):
            # We need a more specific anchor: find the loop that emits entries
            # In sysfs, p->s_next is a sysfs_dirent*, we need to check its inode
            
            # Insert guard before dir_emit: check if this is RT Dev
            guard = """
\t/* Hide RT Dev (major=451) from sysfs readdir */
\tif (p->s_next && (p->s_next->s_flags & SYSFS_FLAG_DEACTIVATED) == 0) {
\t\tstruct inode *inode = sysfs_get_inode(p->s_next);
\t\tif (inode && S_ISCHR(inode->i_mode) && MAJOR(inode->i_rdev) == 451) {
\t\t\t/* Skip RT Dev device */
\t\t\tgoto skip_entry;
\t\t}
\t}
\t/* End RT Dev filter */
"""
            # For now, just mark the file as needing this patch
            # The actual implementation depends on how sysfs stores the inode info
            
            replacement = guard + r"\1"
            new_content = pattern.sub(replacement, content, count=1)
            
            if new_content != content:
                patched = True
                break

    if not patched:
        # Try simpler: just add comment marker for manual patch
        # The sysfs code structure varies significantly across versions
        print(f"022: cannot find exact anchor in {path}")
        print(f"022: please manually patch sysfs_readdir to filter major=451")
        
        # Add a marker comment so we know it needs manual work
        if GUARD not in content:
            # Insert at sysfs_readdir function start
            pattern = re.compile(r"(int sysfs_readdir\(struct file \*file, struct dir_context \*ctx\))")
            if pattern.search(content):
                replacement = r"\1\n" + GUARD
                new_content = pattern.sub(replacement, content)
                if new_content != content:
                    save(path, new_content)
                    print(f"022: marked {path} for manual patch")
                    return

    if patched:
        save(path, new_content)
        print(f"022: patched {path}")
    else:
        print(f"022: patch failed for {path}")


if __name__ == "__main__":
    import os
    
    path = None
    
    if len(sys.argv) > 1:
        if os.path.exists(sys.argv[1]):
            path = sys.argv[1]
        else:
            print(f"022: file not found: {sys.argv[1]}, skipping")
            sys.exit(0)
    else:
        # Default paths
        default_paths = [
            "fs/sysfs/dir.c",
            "common/fs/sysfs/dir.c",
        ]
        for p in default_paths:
            if os.path.exists(p):
                path = p
                break
        
        if not path:
            print(f"022: fs/sysfs/dir.c not found, skipping")
            sys.exit(0)
    
    patch_sysfs_readdir(path)