#!/usr/bin/env python3
"""Hide su/ksud binary paths from execveat/execve for app UIDs via fs/exec.c.

Dual-hook strategy:

  1. do_execveat_common() entry  [PRIMARY]
     The single central function called by both execve and execveat.
     filename is already a struct filename * (kernel pointer), so
     filename->name is used directly — no strncpy_from_user needed.
     IS_ERR check guards against error-pointer callers.
     Returns -ENOENT before any bprm/file setup.

  2. do_open_execat() entry  [SECONDARY / belt-and-suspenders]
     name->name is kernel-space.  Returns ERR_PTR(-ENOENT).
     Handles trees where the path reaches do_open_execat directly.

Patches:
  fs/exec.c  (do_execveat_common  +  do_open_execat)
"""

import re
import sys

GUARD_EV = "/* Hide su/ksud paths from execve/execveat for app UIDs (uid >= 10000) */"
GUARD_OE = "/* Hide su/ksud exec paths from app UIDs via do_open_execat (uid >= 10000) */"

_PATH_LIST = (
    '\t\t\t"/system/bin/su",\n'
    '\t\t\t"/system/xbin/su",\n'
    '\t\t\t"/sbin/su",\n'
    '\t\t\t"/su/bin/su",\n'
    '\t\t\t"/data/local/bin/su",\n'
    '\t\t\t"/data/local/xbin/su",\n'
    '\t\t\t"/data/local/tmp/su",\n'
    '\t\t\t"/data/adb/ksud",\n'
    '\t\t\t"/data/adb/ksu/bin/ksud",\n'
)

# Hook 1 filter block: inserted in SYSCALL_DEFINE5(execveat).
# Hook 1 filter block: inserted at the top of do_execveat_common().
# filename is struct filename * (kernel pointer) — use filename->name directly.
# IS_ERR check guards against error-pointer callers.
# Returns -ENOENT before any bprm/file setup.
_FILTER_EV = (
    '\t' + GUARD_EV + '\n'
    '\tif (current_uid().val >= 10000 && !IS_ERR(filename) && filename->name) {\n'
    '\t\tstatic const char * const __execve_su_paths[] = {\n'
    + _PATH_LIST +
    '\t\t};\n'
    '\t\tint __execve_i;\n'
    '\t\tfor (__execve_i = 0;\n'
    '\t\t     __execve_i < ARRAY_SIZE(__execve_su_paths);\n'
    '\t\t     __execve_i++) {\n'
    '\t\t\tif (!strcmp(filename->name, __execve_su_paths[__execve_i]))\n'
    '\t\t\t\treturn -ENOENT;\n'
    '\t\t}\n'
    '\t}\n'
)

# Hook 2 filter block: inserted in do_open_execat.
# name->name is kernel-space.  Returns ERR_PTR(-ENOENT).
_FILTER_OE = (
    '\t' + GUARD_OE + '\n'
    '\tif (current_uid().val >= 10000 && name && name->name) {\n'
    '\t\tstatic const char * const __execat_su_paths[] = {\n'
    + _PATH_LIST +
    '\t\t};\n'
    '\t\tint __execat_i;\n'
    '\t\tfor (__execat_i = 0;\n'
    '\t\t     __execat_i < ARRAY_SIZE(__execat_su_paths);\n'
    '\t\t     __execat_i++) {\n'
    '\t\t\tif (!strcmp(name->name, __execat_su_paths[__execat_i]))\n'
    '\t\t\t\treturn ERR_PTR(-ENOENT);\n'
    '\t\t}\n'
    '\t}\n'
)


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


# ── Hook 1: patch do_execveat_common ─────────────────────────────────────────


def patch_execveat_common(path):
    """Insert su-path filter at the entry of do_execveat_common().

    do_execveat_common() is the single central function called by both
    execve() and execveat() in all Linux 5.10 trees.  By the time we
    reach it, filename is a valid struct filename * (or ERR_PTR), so
    filename->name is a kernel-space string — no strncpy_from_user needed.

    We insert immediately after the opening brace of the function body,
    guarded by IS_ERR() so that error-pointer callers are handled safely.
    """
    content = load(path)
    if GUARD_EV in content:
        print(f"014: {path} do_execveat_common already patched, skipping")
        return

    # Match the full function signature (may span multiple lines) up to
    # and including the opening brace, then the newline that follows.
    # [^{]+ matches across newlines because [^{] is not dot.
    pattern = re.compile(
        r"(static int do_execveat_common\b[^{]+\{)\n"
    )
    m = pattern.search(content)
    if not m:
        hits = [
            f"  L{i+1}: {l.rstrip()}"
            for i, l in enumerate(content.splitlines())
            if "do_execveat_common" in l
        ]
        print(
            f"ERROR: do_execveat_common anchor not found in {path}",
            file=sys.stderr,
        )
        for h in hits[:10]:
            print(h, file=sys.stderr)
        sys.exit(1)

    # Insert filter right after the opening brace + newline.
    insert_pos = m.end(0)
    new_content = content[:insert_pos] + _FILTER_EV + content[insert_pos:]
    save(path, new_content)
    print(f"014: {path} do_execveat_common patched successfully")


# ── Hook 2: patch do_open_execat ─────────────────────────────────────────────


def patch_exec_openat(path):
    """Insert filter at the start of do_open_execat() — belt-and-suspenders."""
    content = load(path)
    if GUARD_OE in content:
        print(f"014: {path} do_open_execat already patched, skipping")
        return

    # Flexible match: any do_open_execat variant
    pattern = re.compile(
        r"(static struct file \*do_open_execat\b[^{]+\{)\n"
        r"(\tstruct file \*file;)"
    )
    m = pattern.search(content)
    if not m:
        # Fallback: body starts with struct open_flags, int, etc.
        pattern2 = re.compile(
            r"(static struct file \*do_open_execat\b[^{]+\{)\n"
            r"(\t(?:struct|int)\b)"
        )
        m = pattern2.search(content)

    if not m:
        hits = [
            f"  L{i+1}: {l.rstrip()}"
            for i, l in enumerate(content.splitlines())
            if "do_open_execat" in l
        ]
        print(
            f"WARNING: do_open_execat anchor not found in {path} -- skipping secondary hook",
            file=sys.stderr,
        )
        for h in hits[:10]:
            print(h, file=sys.stderr)
        return  # Not fatal -- primary hook covers the path

    new_content = (
        content[: m.end(1)] + "\n" + _FILTER_OE + content[m.end(1) + 1 :]
    )
    save(path, new_content)
    print(f"014: {path} (do_open_execat) patched successfully")


# ── main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    patch_execveat_common("fs/exec.c")   # primary hook
    patch_exec_openat("fs/exec.c")        # belt-and-suspenders
