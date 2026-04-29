# Cloudy Dev KPM Makefile for kernel built-in compilation
# Usage: Place this in drivers/cloudydev/Makefile
#
# NOTE: -fno-lto disables ThinLTO for this driver to prevent __compiletime_assert_321
#       linker errors caused by cross-module inlining. However, -fno-lto conflicts
#       with -fsanitize=cfi (CFI requires LTO), so we must also disable CFI.

# Disable LTO
ccflags-y += -fno-lto

# Disable CFI (requires LTO, conflicts with -fno-lto)
CFLAGS_cloudydev_ksm.o := -fno-sanitize=cfi

obj-$(CONFIG_CLOUDYDEV) += cloudydev_ksm.o