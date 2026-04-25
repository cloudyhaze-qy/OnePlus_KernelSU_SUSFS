#!/usr/bin/env python3
"""Inject /proc/modules hider for KernelSU/SUSFS into kernel/module.c.

For app UIDs (uid >= 10000) reading /proc/modules, skip entries whose
names match the deny-list {"kernelsu", "susfs"}.

Uses regex text-search to locate the MODULE_STATE_UNFORMED guard in
m_show(), so it is robust against line-number drift across kernel versions.
"""

import re
import sys

TARGET = "kernel/module.c"

# Anchor on the three lines that end the UNFORMED guard in m_show().
# We match them literally so the substitution is idempotent-safe.
PATTERN = re.compile(
    r"(/\* We always ignore unformed modules\. \*/\n"
    r"\tif \(mod->state == MODULE_STATE_UNFORMED\)\n"
    r"\t\treturn 0;)"
)

INJECTION = (
    "\n"
    "\n"
    "\t/* Hide KernelSU/SUSFS modules from app UIDs (uid >= 10000). */\n"
    "\tif (current_uid().val >= 10000) {\n"
    '\t\tstatic const char * const denylist[] = {\n'
    '\t\t\t"kernelsu", "susfs",\n'
    "\t\t};\n"
    "\t\tint _i;\n"
    "\t\tfor (_i = 0; _i < ARRAY_SIZE(denylist); _i++)\n"
    "\t\t\tif (strstr(mod->name, denylist[_i]))\n"
    "\t\t\t\treturn 0;\n"
    "\t}"
)

try:
    with open(TARGET, "r", encoding="utf-8") as fh:
        content = fh.read()
except OSError as exc:
    print(f"ERROR: cannot open {TARGET}: {exc}", file=sys.stderr)
    sys.exit(1)

# Idempotency guard – skip if already applied.
if "Hide KernelSU/SUSFS modules from app UIDs" in content:
    print(f"004: {TARGET} already patched, skipping")
    sys.exit(0)

m = PATTERN.search(content)
if not m:
    print(
        f"ERROR: anchor pattern not found in {TARGET}\n"
        "  Expected: '/* We always ignore unformed modules. */'"
        " followed by MODULE_STATE_UNFORMED guard",
        file=sys.stderr,
    )
    sys.exit(1)

new_content = PATTERN.sub(r"\1" + INJECTION, content, count=1)

with open(TARGET, "w", encoding="utf-8") as fh:
    fh.write(new_content)

print(f"004: {TARGET} patched successfully")
