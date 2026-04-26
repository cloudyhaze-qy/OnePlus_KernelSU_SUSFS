#!/usr/bin/env python3
"""Spoof bootloader unlock indicators in /proc/cmdline output.

Android's init process reads /proc/cmdline at startup (PID 1) and converts
androidboot.* parameters into ro.boot.* system properties:
  androidboot.verifiedbootstate=orange  →  ro.boot.verifiedbootstate=orange
  androidboot.flash.locked=0            →  ro.boot.flash.locked=0

These properties are then stored in the Android property service shared
memory (/dev/__properties__/) and read by all processes including games.

ACE / libturinggame.so reads:
  ro.boot.verifiedbootstate == "orange"  → unlocked bootloader detected
  ro.boot.flash.locked      == "0"       → bootloader unlock detected

Fix: patch cmdline_proc_show() in fs/proc/cmdline.c to substitute the
dangerous values in its output BEFORE Android init ever reads them.
Since init reads /proc/cmdline once at boot to build its property table,
our substitution causes init to set the correct (spoofed) values:
  ro.boot.verifiedbootstate = green  (looks like locked bootloader)
  ro.boot.flash.locked      = 1      (looks like locked bootloader)

Substitution is done for ALL readers (not just app UIDs) so init itself
sees the clean values when it runs at PID 1.
"""

import re
import sys

GUARD = "/* Spoof bootloader unlock indicators in /proc/cmdline (anti-cheat) */"

# Inline C block that replaces seq_puts(m, saved_command_line) in
# cmdline_proc_show().  It iterates the cmdline string and substitutes:
#   androidboot.verifiedbootstate=orange  →  androidboot.verifiedbootstate=green[sp]
#   androidboot.flash.locked=0            →  androidboot.flash.locked=1
# The substitutions are length-matched so no reallocation is needed and
# the resulting cmdline stays syntactically valid.
_SPOOF_BLOCK = """\
\t{GUARD}
\t{{
\t\tconst char *_s = saved_command_line;
\t\tconst char *_e = _s + strlen(_s);
\t\twhile (_s < _e) {{
\t\t\tconst char *_pv = strstr(_s,
\t\t\t\t"androidboot.verifiedbootstate=orange");
\t\t\tconst char *_pf = strstr(_s, "androidboot.flash.locked=0");
\t\t\t/* Pick whichever target pattern appears first */
\t\t\tif (_pv && (!_pf || _pv <= _pf)) {{
\t\t\t\tseq_write(m, _s, _pv - _s);
\t\t\t\t/* "orange"(6) → "green "(6) — same length, keeps spacing */
\t\t\t\tseq_puts(m, "androidboot.verifiedbootstate=green ");
\t\t\t\t_s = _pv + sizeof("androidboot.verifiedbootstate=orange") - 1;
\t\t\t}} else if (_pf) {{
\t\t\t\tseq_write(m, _s, _pf - _s);
\t\t\t\t/* "=0"(1) → "=1"(1) — same length */
\t\t\t\tseq_puts(m, "androidboot.flash.locked=1");
\t\t\t\t_s = _pf + sizeof("androidboot.flash.locked=0") - 1;
\t\t\t}} else {{
\t\t\t\tseq_write(m, _s, _e - _s);
\t\t\t\t_s = _e;
\t\t\t}}
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


# ── patch: fs/proc/cmdline.c → cmdline_proc_show ─────────────────────────────


def patch_cmdline(path):
    """Replace seq_puts(m, saved_command_line) in cmdline_proc_show() with
    a substitution loop that rewrites the dangerous bootloader-state params."""

    content = load(path)

    if GUARD in content:
        print(f"011: {path} already patched, skipping")
        return

    # Anchor: the sole seq_puts call in cmdline_proc_show.
    # In Linux 5.10 the entire function is:
    #   static int cmdline_proc_show(struct seq_file *m, void *v)
    #   {
    #       seq_puts(m, saved_command_line);
    #       seq_putc(m, '\n');
    #       return 0;
    #   }
    pattern = re.compile(
        r"(static int cmdline_proc_show\(struct seq_file \*m, void \*v\)\n"
        r"\{\n)"
        r"(\tseq_puts\(m, saved_command_line\);\n)"
    )

    m = pattern.search(content)
    if not m:
        print(
            f"ERROR: anchor for cmdline_proc_show not found in {path}\n"
            "  Expected:\n"
            "    static int cmdline_proc_show(struct seq_file *m, void *v)\n"
            "    {\n"
            "        seq_puts(m, saved_command_line);",
            file=sys.stderr,
        )
        sys.exit(1)

    # Replace the seq_puts line with our substitution block
    new_content = (
        content[: m.start(2)]
        + _SPOOF_BLOCK
        + content[m.end(2) :]
    )

    # Ensure linux/string.h is included (provides strlen/strstr)
    if "#include <linux/string.h>" not in new_content:
        # Insert after the last existing #include line in the file header
        inc_pat = re.compile(r"((?:#include [^\n]+\n)+)")
        im = inc_pat.search(new_content)
        if im:
            new_content = (
                new_content[: im.end()]
                + "#include <linux/string.h>\n"
                + new_content[im.end() :]
            )

    save(path, new_content)
    print(f"011: {path} (cmdline_proc_show) patched successfully")


# ── main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    patch_cmdline("fs/proc/cmdline.c")
