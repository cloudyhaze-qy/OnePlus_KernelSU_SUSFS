#!/usr/bin/env python3
"""Block open() of RT Dev KPM char device (major=451) from app UIDs.

patch 010 hides the device node from stat()/fstat()/statx() by patching
vfs_statx().  However, open() does NOT call vfs_statx():

  sys_openat()
   └─ do_sys_open()
       └─ do_filp_open()
           └─ path_openat()
               └─ do_open()
                   └─ vfs_open()
                       └─ inode->i_fop->open()   ← chrdev_open() for char devs
                           └─ kobj_lookup()
                               └─ RT Dev driver's .open()

ACE's dev_Sch() flow:
  1. opendir("/dev/")  → iterate_dir  (no stat needed)
  2. readdir()         → sees the 6-char random name entry
  3. open(path, RDWR)  → succeeds even when stat returns ENOENT!
  4. ioctl(fd, RT_MAGIC, buf) → confirms RT Dev present

Fix: patch chrdev_open() in fs/char_dev.c to return -ENOENT when:
  - MAJOR(inode->i_rdev) == 451, AND
  - current_uid().val >= 10000 (app UID)

This closes the open() bypass that patch 010 leaves open.
"""

import re
import sys

GUARD = "/* Hide RT Dev char device open (major=451) from app UIDs (uid >= 10000) */"

_HIDE_BLOCK = """\
\t{GUARD}
\tif (MAJOR(inode->i_rdev) == 451 && current_uid().val >= 10000)
\t\treturn -ENOENT;
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


# ── patch: fs/char_dev.c → chrdev_open ───────────────────────────────────────


def patch_chrdev(path):
    """Inject the major=451 UID check at the very start of chrdev_open()."""

    content = load(path)

    if GUARD in content:
        print(f"012: {path} already patched, skipping")
        return

    # Anchor: chrdev_open function opening.
    # In Linux 5.10, chrdev_open begins with:
    #
    #   static int chrdev_open(struct inode *inode, struct file *filp)
    #   {
    #       const struct file_operations *fops;
    #       struct cdev *p;
    #
    # Capture everything up to and including the opening brace + newline so
    # we can inject our check as the very first statement in the function.
    pattern = re.compile(
        r"(static int chrdev_open\(struct inode \*inode, struct file \*filp\)\n"
        r"\{)\n"
        r"(\tconst struct file_operations \*fops;)"
    )

    m = pattern.search(content)
    if not m:
        print(
            f"ERROR: anchor for chrdev_open not found in {path}\n"
            "  Expected:\n"
            "    static int chrdev_open(struct inode *inode, struct file *filp)\n"
            "    {\n"
            "        const struct file_operations *fops;",
            file=sys.stderr,
        )
        sys.exit(1)

    insert_pos = m.end(1) + 1  # right after opening brace + \n
    new_content = (
        content[: m.end(1)]
        + "\n"
        + _HIDE_BLOCK
        + content[m.end(1) + 1 :]
    )

    save(path, new_content)
    print(f"012: {path} (chrdev_open) patched successfully")


# ── main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    patch_chrdev("fs/char_dev.c")
