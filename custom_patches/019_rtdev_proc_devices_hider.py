#!/usr/bin/env python3
"""Hide RT Dev char device major=451 from /proc/devices for app UIDs.

patches 010/012/013 cover:
  stat() / fstat()    → vfs_statx     (010)
  open()              → chrdev_open   (012)
  getdents64 in /dev/ → dcache_readdir(013)

But /proc/devices is a seq_file backed by devinfo_show() in
fs/proc/devices.c (or show_chrdev_range() in fs/char_dev.c).
It lists ALL registered char device majors for ANY process, including
app UIDs (uid >= 10000).

When the RT Dev KPM is loaded:
  $ cat /proc/devices | grep 451
  Character devices:
    451 <class_name>

ACE / libtersafe reads /proc/devices directly via SVC #63 (read syscall)
to enumerate registered char devices and detect unknown majors.
The game can confirm presence of RT Dev major without ever stat()-ing or
opening the /dev/ node.

Fix: Inject a skip guard in devinfo_show() (fs/proc/devices.c) that
returns 0 (skip this seq entry) when:
  - index i == 451 (character device major 451)
  - current_uid().val >= 10000 (app UID)

devinfo_show() is called once per major index (0..CHRDEV_MAJOR_MAX-1),
so the check `i == 451` is exact and has zero overhead for other majors.

Alternatively, the guard can be placed in show_chrdev_range()
(fs/char_dev.c) which is also called by devinfo_show.  We prefer
devinfo_show because it is the sole /proc consumer, avoiding unintended
side-effects on other users of show_chrdev_range.

Linux 5.10 devinfo_show (fs/proc/devices.c):

    static int devinfo_show(struct seq_file *f, void *v)
    {
        int i = *(loff_t *) v;

        if (i < CHRDEV_MAJOR_MAX) {
            if (i == 0)
                seq_puts(f, "Character devices:\\n");
            show_chrdev_range(f, i);          ← inject before this
        }
        if (i == CHRDEV_MAJOR_MAX)
            seq_puts(f, "\\nBlock devices:\\n");
        if (i > CHRDEV_MAJOR_MAX)
            show_blkdev(f, i - CHRDEV_MAJOR_MAX - 1);
        return 0;
    }
"""

import re
import sys

TARGET = "fs/proc/devices.c"

GUARD = ("/* Hide RT Dev char device major=451 from /proc/devices"
         " for app UIDs (uid >= 10000) */")

# Injected immediately before show_chrdev_range(f, i) so that
# the entry is simply not printed.
_HIDE_BLOCK = """\
\t\t{GUARD}
\t\tif (current_uid().val >= 10000 && i == 451)
\t\t\treturn 0;
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


def patch_devinfo(path):
    """Inject the major=451 skip guard in devinfo_show()."""

    content = load(path)

    if GUARD in content:
        print(f"019: {path} already patched, skipping")
        return

    # Try multiple anchor patterns for different kernel versions
    anchors = [
        r"\t\tshow_chrdev_range\(f, i\);",
        r"\bchrdev_show\(f, i\);",
        r"\bproc_dev_show\(f, v\);",
        r"show_chrdev\(",
        r"\bdev_show\(struct seq_file",
        r"\ti == 0",  # Last resort: at the i==0 check
    ]
    
    anchor_found = None
    for anchor in anchors:
        pattern = re.compile(anchor)
        if pattern.search(content):
            anchor_found = anchor
            break
    
    if not anchor_found:
        print(f"019: ERROR - no anchor found in {path}")
        print(f"019: Current kernel may differ from standard Linux 5.10.")
        print(f"019: Please manually add RT Dev filter.")
        sys.exit(1)

    # Find match for insertion
    pattern = re.compile(anchor_found)
    m = pattern.search(content)
    if not m:
        print(f"019: FAILED to match anchor {anchor_found}")
        sys.exit(1)

    # Insert guard at the matched position
    insert_pos = m.start()
    new_content = content[:insert_pos] + _HIDE_BLOCK + content[insert_pos:]
    save(path, new_content)
    print(f"019: {path} patched successfully")


if __name__ == "__main__":
    patch_devinfo(TARGET)
