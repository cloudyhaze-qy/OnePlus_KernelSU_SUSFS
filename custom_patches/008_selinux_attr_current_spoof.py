#!/usr/bin/env python3
"""Spoof /proc/self/attr/current for app UIDs to return untrusted_app domain.

libturinggame.so sub_26D08 opens /proc/self/attr/current and splits the
SELinux context string by ":" to extract the domain field.  If the game
process is somehow running with a non-standard SELinux domain (e.g., after
KernelSU root grant changes the context, or a cheat tool injects into the
process), the anti-cheat reports it to the server as a risk signal.

Confirmed detection vector:
  sub_26D08 (libturinggame.so):
    fopen(/proc/self/attr/current, "r")  [qword_3C088 -> XOR-0xe3 decoded]
    fread → parse by ":" → extract domain field
    → sent as telemetry to Tencent anti-cheat server

Mitigation strategy:
  In proc_pid_attr_read() (fs/proc/base.c), after security_getprocattr()
  returns the SELinux context string:
    - caller uid >= 10000 (Android app)
    - reading their OWN process attr (task == current)
    - attr name == "current"
    - returned string does NOT contain "untrusted_app"
  → replace with "u:r:untrusted_app:s0\\n"

This keeps the label correct for normal app processes (which already have
untrusted_app domain and will NOT trigger the replacement) while masking
any anomalous domain that would be reported as suspicious.

Patches:
  fs/proc/base.c  (proc_pid_attr_read)
"""

import re
import sys

GUARD = "/* Spoof /proc/self/attr/current domain for app UIDs (uid >= 10000) */"

_SPOOF_BLOCK = '''\
\t{GUARD}
\tif (length > 0 && p &&
\t    current_uid().val >= 10000 &&
\t    strcmp(file->f_path.dentry->d_name.name, "current") == 0 &&
\t    !strnstr(p, "untrusted_app", (size_t)length)) {{
\t\tkfree(p);
\t\tp = kstrdup("u:r:untrusted_app:s0\\n", GFP_KERNEL);
\t\tif (p)
\t\t\tlength = (ssize_t)strlen(p);
\t\telse
\t\t\tlength = -ENOMEM;
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


# ── patch: fs/proc/base.c → proc_pid_attr_read ───────────────────────────────

def patch_proc_base(path):
    """Insert domain-spoof block in proc_pid_attr_read(), right after
    put_task_struct(task) and before the simple_read_from_buffer call.

    In Linux 5.10 (OnePlus sm8475) the function body ends with:

        put_task_struct(task);
        if (length > 0)
                length = simple_read_from_buffer(buf, count, ppos, p, length);
        kfree(p);
        return length;

    We insert the spoof block between put_task_struct and the 'if (length > 0)'
    check, so we can replace 'p' before it gets passed to the user buffer.
    """

    content = load(path)

    if GUARD in content:
        print(f"008: {path} already patched, skipping")
        return

    # Anchor: the unique sequence in proc_pid_attr_read:
    #   put_task_struct(task);
    #   if (length > 0)
    #       length = simple_read_from_buffer(...)
    # This combination only appears once in fs/proc/base.c.
    pattern = re.compile(
        r"(\tput_task_struct\(task\);\n)"
        r"(\tif \(length > 0\)\n"
        r"\t\tlength = simple_read_from_buffer)"
    )

    m = pattern.search(content)
    if not m:
        print(
            f"ERROR: anchor for proc_pid_attr_read not found in {path}\n"
            "  Expected: put_task_struct(task); followed by "
            "if (length > 0) ... simple_read_from_buffer",
            file=sys.stderr,
        )
        sys.exit(1)

    insert_pos = m.end(1)   # right after put_task_struct(task);\n
    new_content = content[:insert_pos] + _SPOOF_BLOCK + content[insert_pos:]

    save(path, new_content)
    print(f"008: {path} (proc_pid_attr_read) patched successfully")


# ── main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    patch_proc_base("fs/proc/base.c")
