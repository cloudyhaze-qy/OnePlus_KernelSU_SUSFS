#!/usr/bin/env python3
"""Hide RT Dev KPM char device (major=451) from inotify/fsnotify events.

When a device is created in /dev/, kernel notifies watchers via:
  1. inotify - user space watches /dev/ via inotify_init() + inotify_add_watch()
  2. fanotify - similar but for filesystem-wide events
  3. dnotify - legacy directory notification

All these notification mechanisms flow through fsnotify() which is
called when the inode is changed (IN_CREATE for new device node).

The scan pattern:
  1. ACE monitors inotify events on /dev/
  2. When IN_CREATE event fires, extracts filename from event
  3. If filename is 6-char alphanumeric → RT Dev detected

We filter at fsnotify() entry point: skip reporting events for
inodes that belong to RT Dev devices (major=451 char device).

Injection points (multiple):
  fs/notify/inotify.c  - inotify_inode_queue_event()
  fs/notify/fanotify.c - fanotify_handle_event()
  fs/dnotify.c        - dnotify()

Patches:
  fs/notify/inotify.c  (inotify_inode_queue_event)
  fs/notify/fanotify.c (fanotify_handle_event)
  fs/dnotify.c        (dnotify)
"""

import re
import sys

GUARD = "/* Hide RT Dev (major=451) from inotify/fsnotify */"

# Filter block: skip fsnotify for RT Dev
_HIDE_BLOCK = """
{GUARD}
{{
    // Check if this is a new char device with major=451
    if (mask & (IN_CREATE | IN_MOVED_TO)) {{
        struct inode *inode = file_inode(event->fat->file);
        if (inode && S_ISCHR(inode->i_mode) && MAJOR(inode->i_rdev) == 451) {{
            // Skip inotify/fanotify event for RT Dev
            return 0;
        }}
    }}
}}
""".format(GUARD=GUARD)

# Alternative simpler check: check the filename in the event
_ALT_HIDE_BLOCK = """
{GUARD}
{{
    if (mask & (IN_CREATE | IN_MOVED_TO)) {{
        char *name = NULL;
        // Try to get name from event data
        // If name matches 6-char alphanumeric pattern, skip event
        if (name && strlen(name) == 6) {{
            int is_alnum = 1;
            for (int i = 0; i < 6; i++) {{
                char c = name[i];
                if (!((c >= 'a' && c <= 'z') ||
                     (c >= 'A' && c <= 'Z') ||
                     (c >= '0' && c <= '9'))) {{
                    is_alnum = 0;
                    break;
                }}
            }}
            if (is_alnum) {{
                return 0;  // Skip RT Dev event
            }}
        }}
    }}
}}
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


# -- patch: fs/notify/inotify.c ----------------------------

def patch_inotify(path):
    """Insert RT Dev filter in inotify_inode_queue_event()."""

    content = load(path)

    if GUARD in content:
        print(f"021: {path} already patched, skipping")
        return

    # Anchor: inotify_inode_queue_event() function entry or event mask check
    # Pattern: int inotify_inode_queue_event(...)
    pattern = re.compile(
        r"(int inotify_inode_queue_event\(struct inode \*inode,\n"
        r"\s+u32 mask,\n"
        r"\s+const void \*data,\n"
        r"\s+int data_len,\n"
        r"\s+const char \*filename,\n"
        r"\s+struct inode \*dir_inode\))"
    )

    if not pattern.search(content):
        # Try simpler anchor: inotify_inode_queue_event
        pattern = re.compile(r"(int inotify_inode_queue_event\()")

    if not pattern.search(content):
        print(f"021: cannot find inotify_inode_queue_event in {path}")
        return

    # Insert guard at function start
    replacement = r"\1\n" + _HIDE_BLOCK

    new_content = pattern.sub(replacement, content, count=1)

    if new_content == content:
        print(f"021: patch failed for {path}")
        return

    save(path, new_content)
    print(f"021: patched {path}")


# -- patch: fs/notify/fanotify.c -----------------------------

def patch_fanotify(path):
    """Insert RT Dev filter in fanotify_handle_event()."""

    content = load(path)

    if GUARD in content:
        print(f"021: {path} already patched, skipping")
        return

    # Anchor: fanotify_handle_event()
    pattern = re.compile(r"(static int fanotify_handle_event\()")

    if not pattern.search(content):
        print(f"021: cannot find fanotify_handle_event in {path}")
        return

    replacement = r"\1\n" + _HIDE_BLOCK

    new_content = pattern.sub(replacement, content, count=1)

    if new_content == content:
        print(f"021: patch failed for {path}")
        return

    save(path, new_content)
    print(f"021: patched {path}")


# -- patch: fs/dnotify.c --------------------------------

def patch_dnotify(path):
    """Insert RT Dev filter in dnotify."""

    content = load(path)

    if GUARD in content:
        print(f"021: {path} already patched, skipping")
        return

    # Anchor: dnotify() or dnotify_dir_notify()
    pattern = re.compile(r"(void dnotify\(struct dentry \*dir,)")

    if not pattern.search(content):
        print(f"021: cannot find dnotify in {path}")
        return

    replacement = r"\1\n" + _HIDE_BLOCK

    new_content = pattern.sub(replacement, content, count=1)

    if new_content == content:
        print(f"021: patch failed for {path}")
        return

    save(path, new_content)
    print(f"021: patched {path}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <source_file>")
        sys.exit(1)

    path = sys.argv[1]

    # Auto-detect which file to patch
    if "inotify" in path:
        patch_inotify(path)
    elif "fanotify" in path:
        patch_fanotify(path)
    elif "dnotify" in path:
        patch_dnotify(path)
    else:
        print(f"Unknown file: {path}")
        sys.exit(1)