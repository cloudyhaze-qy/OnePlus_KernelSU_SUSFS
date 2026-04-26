#!/usr/bin/env python3
"""Hide su/ksud binary paths from execveat for app UIDs via fs/exec.c.

patch 006 patches do_faccessat (access()) and vfs_statx (stat()) to return
ENOENT for su binary paths.  However, the execveat(2) syscall goes through
a separate code path:

  sys_execveat
   └─ __do_execve_file
       └─ do_open_execat        ← opens the executable file
           └─ filp_open / do_filp_open
               └─ vfs_open

Neither do_faccessat nor vfs_statx is called when opening a file for
exec.  The probe confirms three paths survive as LEAK:

  /system/bin/su  – exec succeeds (errno=0)  → patch 006 does NOT cover this
  /data/adb/ksud  – EACCES (file exists)     → patch 006 does NOT cover this
  /data/adb/ksu/bin/ksud  – EACCES           → patch 006 does NOT cover this

Fix: patch do_open_execat() at its entry point to return ERR_PTR(-ENOENT)
for known su/ksud paths when called by an app UID (≥ 10000).

At the do_open_execat entry, `name->name` is already a kernel-space string
(struct filename has already been copied from userspace), so direct
strcmp() is safe with no strncpy_from_user needed.

Patches:
  fs/exec.c  (do_open_execat)
"""

import re
import sys

GUARD = "/* Hide su/ksud exec paths from app UIDs via do_open_execat (uid >= 10000) */"

# Injected at the very start of do_open_execat(), right after opening brace.
# name->name is the kernel-space copy of the requested exec path.
_FILTER_BLOCK = """\
\t{GUARD}
\tif (current_uid().val >= 10000 && name && name->name) {{
\t\tstatic const char * const __execat_su_paths[] = {{
\t\t\t"/system/bin/su",
\t\t\t"/system/xbin/su",
\t\t\t"/sbin/su",
\t\t\t"/su/bin/su",
\t\t\t"/data/local/bin/su",
\t\t\t"/data/local/xbin/su",
\t\t\t"/data/local/tmp/su",
\t\t\t"/data/adb/ksud",
\t\t\t"/data/adb/ksu/bin/ksud",
\t\t}};
\t\tint __execat_i;
\t\tfor (__execat_i = 0;
\t\t     __execat_i < ARRAY_SIZE(__execat_su_paths);
\t\t     __execat_i++) {{
\t\t\tif (!strcmp(name->name, __execat_su_paths[__execat_i]))
\t\t\t\treturn ERR_PTR(-ENOENT);
\t\t}}
\t}}
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


# ── patch: fs/exec.c → do_open_execat ────────────────────────────────────────

def patch_exec(path):
    """Inject su/ksud path filter at the very start of do_open_execat().

    In Linux 5.10, do_open_execat begins with:

        static struct file *do_open_execat(int fd, struct filename *name, int flags)
        {
            struct file *file;
            int err;
            struct open_flags open_exec_flags = {

    We insert immediately after the opening brace so the check fires
    before any file lookup is attempted.
    """

    content = load(path)

    if GUARD in content:
        print(f"014: {path} already patched, skipping")
        return

    # ── Primary anchor: standard 5.10 do_open_execat signature ───────────────
    pattern = re.compile(
        r"(static struct file \*do_open_execat\("
        r"int fd, struct filename \*name, int flags\)\n"
        r"\{)\n"
        r"(\tstruct file \*file;)"
    )

    m = pattern.search(content)
    if not m:
        # ── Fallback: some trees use __user qualifier or slightly different sig
        pattern2 = re.compile(
            r"(static struct file \*do_open_execat\([^)]+\)\n"
            r"\{)\n"
            r"(\tstruct file \*file;)"
        )
        m = pattern2.search(content)

    if not m:
        print(
            f"ERROR: anchor for do_open_execat not found in {path}\n"
            "  Expected:\n"
            "    static struct file *do_open_execat(int fd, struct filename *name, int flags)\n"
            "    {\n"
            "        struct file *file;",
            file=sys.stderr,
        )
        sys.exit(1)

    # Insert _FILTER_BLOCK right after the opening brace + newline
    insert_pos = m.end(1) + 1  # after "{\n"
    new_content = (
        content[: m.end(1)]
        + "\n"
        + _FILTER_BLOCK
        + content[m.end(1) + 1 :]
    )

    save(path, new_content)
    print(f"014: {path} (do_open_execat) patched successfully")


# ── main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    patch_exec("fs/exec.c")
