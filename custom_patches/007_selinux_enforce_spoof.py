#!/usr/bin/env python3
"""Spoof SELinux enforce state to "1" for app UIDs via selinuxfs.

When a process with UID >= 10000 (Android app) reads /sys/fs/selinux/enforce,
always return "1\\n" (enforcing mode) regardless of the actual SELinux state.

This defeats anti-cheat libraries that read /sys/fs/selinux/enforce to detect
permissive mode.  Confirmed detection vector in libturinggame.so sub_24E98:

  access("/sys/fs/selinux/enforce", F_OK)
  fd = open("/sys/fs/selinux/enforce", O_RDONLY)
  read(fd, buf, 2)          <- buf[0] == '0' means permissive → flag raised

The underlying cause: cheat tools call setenforce(0) before reading game
memory, which flips the enforce file to "0".  This patch makes the file
always read "1" for app-UID callers without changing actual SELinux policy.

Patches:
  security/selinux/selinuxfs.c  (sel_read_enforce)
"""

import re
import sys

GUARD = "/* Spoof SELinux enforce state to 1 for app UIDs (uid >= 10000) */"

# Inserted at the very start of sel_read_enforce(), before any local vars.
# Uses simple_read_from_buffer (already imported by the translation unit) to
# return a synthetic "1\n" payload directly into the caller's user buffer.
_SPOOF_BLOCK = '''\
\t{GUARD}
\tif (current_uid().val >= 10000) {{
\t\tstatic const char __selinux_enforce_spoofed[] = "1\\n";
\t\treturn simple_read_from_buffer(buf, count, ppos,
\t\t\t\t\t__selinux_enforce_spoofed,
\t\t\t\t\tsizeof(__selinux_enforce_spoofed) - 1);
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


# ── patch: security/selinux/selinuxfs.c → sel_read_enforce ──────────────────

def patch_selinuxfs(path):
    """Insert enforce spoof at the top of sel_read_enforce(), before the
    selinux_fs_info local variable declaration."""

    content = load(path)

    if GUARD in content:
        print(f"007: {path} already patched, skipping")
        return

    # Anchor: the unique sel_read_enforce function signature followed by its
    # opening brace and the first local variable.
    #
    # In Linux 5.10 (OnePlus sm8475 tree):
    #   static ssize_t sel_read_enforce(struct file *filp, char __user *buf,
    #   				size_t count, loff_t *ppos)
    #   {
    #   	struct selinux_fs_info *fsi = file_inode(filp)->i_sb->s_fs_info;
    #
    # [^{]+ stops at the opening brace, which is the only { before the body.
    pattern = re.compile(
        r"(static ssize_t sel_read_enforce\([^{]+\{\n)"
        r"([ \t]*struct selinux_fs_info \*fsi)"
    )

    m = pattern.search(content)
    if not m:
        print(
            f"ERROR: anchor for sel_read_enforce not found in {path}",
            file=sys.stderr,
        )
        sys.exit(1)

    # Insert the spoof block right after the opening brace newline, before
    # the first local variable.
    insert_pos = m.end(1)
    new_content = content[:insert_pos] + _SPOOF_BLOCK + content[insert_pos:]

    save(path, new_content)
    print(f"007: {path} (sel_read_enforce) patched successfully")


# ── main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    patch_selinuxfs("security/selinux/selinuxfs.c")
