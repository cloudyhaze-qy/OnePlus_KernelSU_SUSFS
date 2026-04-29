# Cloudy Dev KPM Makefile for kernel built-in compilation
# Usage: Place this in drivers/cloudydev/Makefile
#
# -fno-lto: prevents ThinLTO cross-module inlining of kernel __copy_from_user_overflow
# helpers, which contain __compiletime_assert_321 (a linker-group member that
# is not available during ThinLTO linking of vmlinux.o).
# Note: CFI_CLANG is disabled in the kernel config (via action.yml) so
# -flto=thin is present without -fsanitize=cfi (no conflict).

# ccflags-y += -fno-lto

obj-$(CONFIG_CLOUDYDEV) += cloudydev_ksm.o