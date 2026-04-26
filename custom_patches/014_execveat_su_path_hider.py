#!/usr/bin/env python3
"""Hide su/ksud binary paths from execveat for app UIDs via fs/exec.c.

Dual-hook strategy to handle OEM trees where do_open_execat is inlined:

  1. SYSCALL_DEFINE5(execveat) entry  [PRIMARY]
     Inserted between the lookup_flags initialisation and the
     `return do_execveat_common()` call.  At this point `filename`
     is still the raw const char __user * from userspace.
     strncpy_from_user() copies it; no struct filename to free on
     early return.  Fires before do_execveat_common / do_open_execat
     and is immune to do_open_execat being inlined by the compiler.

  2. do_open_execat entry  [SECONDARY / belt-and-suspenders]
     name->name is already kernel-space.  Returns ERR_PTR(-ENOENT).
     Handles any path that reaches do_open_execat directly.

Patches:
  fs/exec.c  (SYSCALL_DEFINE5(execveat)  +  do_open_execat)
"""

import re
import sys

GUARD_EV = "/* Hide su/ksud paths from execveat syscall for app UIDs (uid >= 10000) */"
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
# filename is const char __user * — use strncpy_from_user.
# Returns -ENOENT directly from the syscall; no struct filename to free.
_FILTER_EV = (
    '\t' + GUARD_EV + '\n'
    '\tif (current_uid().val >= 10000 && filename) {\n'
    '\t\tstatic const char * const __ev_su_paths[] = {\n'
    + _PATH_LIST +
    '\t\t};\n'
    '\t\tchar __ev_buf[128];\n'
    '\t\tlong __ev_n = strncpy_from_user(__ev_buf, filename,\n'
    '\t\t\t\t\t\tsizeof(__ev_buf) - 1);\n'
    '\t\tif (__ev_n > 0) {\n'
    '\t\t\tint __ev_i;\n'
    "\t\t\t__ev_buf[__ev_n] = '\\0';\n"
    '\t\t\tfor (__ev_i = 0;\n'
    '\t\t\t     __ev_i < ARRAY_SIZE(__ev_su_paths);\n'
    '\t\t\t     __ev_i++) {\n'
    '\t\t\t\tif (!strcmp(__ev_buf, __ev_su_paths[__ev_i]))\n'
    '\t\t\t\t\treturn -ENOENT;\n'
    '\t\t\t}\n'
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


# ── Hook 1: patch SYSCALL_DEFINE5(execveat) ──────────────────────────────────


def patch_execveat_syscall(path):
    """Insert su-path filter at the start of SYSCALL_DEFINE5(execveat).

    Two tree variants are handled:

    Variant A (vanilla 5.10 / some OEM trees):
        int lookup_flags = (flags & AT_EMPTY_PATH) ? LOOKUP_EMPTY : 0;
        return do_execveat_common(fd, getname_flags(filename, ...),
        We insert between these two lines.

    Variant B (SUSFS/KSU-modified trees — confirmed by CI diagnostics):
        SYSCALL_DEFINE5(execveat) begins with a flags-validation guard:
            if ((flags & ~(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH)) != 0)
                return -EINVAL;
        followed by:
            if (flags & AT_EMPTY_PATH)
        We insert after the -EINVAL early return.

    In both cases filename is still the raw const char __user * so
    strncpy_from_user is needed; there is nothing to free on early return.
    """
    content = load(path)
    if GUARD_EV in content:
        print(f"014: {path} execveat syscall already patched, skipping")
        return

    # ── Variant A: lookup_flags line immediately before do_execveat_common ──
    pattern_a1 = re.compile(
        r"(\tint lookup_flags = \(flags & AT_EMPTY_PATH\) \? LOOKUP_EMPTY : 0;\n)"
        r"(\n\treturn do_execveat_common\(fd,)"
    )
    m = pattern_a1.search(content)
    if not m:
        pattern_a2 = re.compile(
            r"(\tint lookup_flags = \(flags & AT_EMPTY_PATH\) \? LOOKUP_EMPTY : 0;\n)"
            r"(\treturn do_execveat_common\(fd,)"
        )
        m = pattern_a2.search(content)

    if m:
        new_content = content[: m.end(1)] + _FILTER_EV + content[m.start(2):]
        save(path, new_content)
        print(f"014: {path} SYSCALL_DEFINE5(execveat) patched successfully (variant A)")
        return

    # ── Variant B: flags validation at the top of the syscall body ──
    # Insert after "return -EINVAL;" and before the next "if (flags & AT_EMPTY_PATH)"
    pattern_b1 = re.compile(
        r"(\tif \(\(flags & ~\(AT_SYMLINK_NOFOLLOW \| AT_EMPTY_PATH\)\) != 0\)\n"
        r"\t\treturn -EINVAL;\n)"
        r"(\n\tif \(flags & AT_EMPTY_PATH\))"
    )
    m = pattern_b1.search(content)
    if not m:
        # Same but no blank line between -EINVAL and AT_EMPTY_PATH check
        pattern_b2 = re.compile(
            r"(\tif \(\(flags & ~\(AT_SYMLINK_NOFOLLOW \| AT_EMPTY_PATH\)\) != 0\)\n"
            r"\t\treturn -EINVAL;\n)"
            r"(\tif \(flags & AT_EMPTY_PATH\))"
        )
        m = pattern_b2.search(content)

    if m:
        new_content = content[: m.end(1)] + _FILTER_EV + content[m.start(2):]
        save(path, new_content)
        print(f"014: {path} SYSCALL_DEFINE5(execveat) patched successfully (variant B)")
        return

    # ── Both variants failed ──
    diag = [
        f"  L{i+1}: {l.rstrip()}"
        for i, l in enumerate(content.splitlines())
        if "AT_EMPTY_PATH" in l or "do_execveat_common" in l
        or "AT_SYMLINK_NOFOLLOW" in l
    ]
    print(
        f"ERROR: SYSCALL_DEFINE5(execveat) anchor not found in {path}",
        file=sys.stderr,
    )
    for l in diag[:20]:
        print(l, file=sys.stderr)
    sys.exit(1)


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
    patch_execveat_syscall("fs/exec.c")   # primary hook
    patch_exec_openat("fs/exec.c")        # belt-and-suspenders
