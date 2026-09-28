#ifndef LAPY_NATIVE_VFS_SYSCALL_H
#define LAPY_NATIVE_VFS_SYSCALL_H

#include <errno.h>
#include <stdint.h>
#include <sys/syscall.h>

#if !defined(__x86_64__) || SYS_fchdir != 13 || SYS_chroot != 61
#error "This wrapper requires the PS5 x86-64 syscall ABI"
#endif

/* SDK libc's raw wrappers do not translate the FreeBSD carry flag to errno.
 * These one-argument VFS syscalls succeed with zero, or return a positive errno.
 * Requires the payload SDK's normal syscall execution setup. */
static inline int lapy_vfs_syscall(long number, uintptr_t argument)
{
    long value;
    unsigned char failed;
    __asm__ volatile("syscall\n\tsetc %1"
                     : "=a"(value), "=qm"(failed)
                     : "a"(number), "D"(argument)
                     : "rcx", "r11", "memory", "cc");
    return failed ? (value > 0 && value <= 4095 ? (int)value : EIO)
                  : (value == 0 ? 0 : EPROTO);
}

static inline int lapy_vfs_fchdir(int fd)
{
    return lapy_vfs_syscall(SYS_fchdir, (uintptr_t)fd);
}

static inline int lapy_vfs_chroot(const char *path)
{
    return lapy_vfs_syscall(SYS_chroot, (uintptr_t)path);
}

#endif
