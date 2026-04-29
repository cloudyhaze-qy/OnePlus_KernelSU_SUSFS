# Cloudy Dev KPM Makefile for kernel built-in compilation
# Usage: Place this in drivers/cloudydev/Makefile
#
# NOTE: -fno-lto is required to prevent ThinLTO from importing kernel
#       overflow-check functions (__copy_from_user_overflow, etc.) which
#       contain __compiletime_assert_321. The driver works correctly with
#       native kernel functions; LTO cross-module inlining causes link errors.

# ccflags-y += -fno-lto

obj-$(CONFIG_CLOUDYDEV) += cloudydev_ksm.o