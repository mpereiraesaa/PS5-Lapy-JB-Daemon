#ifndef LAPY_VFS_PREREQUISITES_H
#define LAPY_VFS_PREREQUISITES_H

#include <errno.h>
#include <ps5/kernel.h>
#include <sys/sysctl.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <unistd.h>

/* Implemented by the pinned SDK CRT, though omitted from its public header. */
extern intptr_t kernel_get_ucred_prison(pid_t pid);

static int log_directory_fd_inventory(void)
{
    errno = 0;
    int limit = getdtablesize(), open_count = 0, directories = 0;
    int table_error = limit < 0 ? errno : 0;
    struct rlimit rlim = {0};
    int rlim_error = getrlimit(RLIMIT_NOFILE, &rlim) < 0 ? errno : 0;
    ps5log_printf(PS5LOG_MARK, "vfs_fd_limit table=%d table_error=%d rlimit=%llu rlimit_error=%d",
                  limit, table_error, (unsigned long long)rlim.rlim_cur, rlim_error);
    if (!rlim_error && rlim.rlim_cur > 0 && rlim.rlim_cur <= 32768 &&
        (limit <= 0 || rlim.rlim_cur > (rlim_t)limit))
        limit = (int)rlim.rlim_cur;
    if (limit <= 0 || limit > 32768) return E2BIG;
    for (int fd = 0; fd < limit; ++fd) {
        struct stat st;
        if (fstat(fd, &st) < 0) {
            if (errno == EBADF) continue;
            return errno;
        }
        ++open_count;
        if (S_ISDIR(st.st_mode)) ++directories;
    }
    ps5log_printf(PS5LOG_MARK, "vfs_descriptors scanned=%d open=%d directories=%d",
                  limit, open_count, directories);
    return 0;
}

/* Diagnostic booleans only; no kernel addresses or credential values leave
 * the process. Unavailable sysctls are reported, not assumed. */
static int log_vfs_prerequisites(void)
{
    intptr_t cred = kernel_get_proc_ucred(getpid());
    uint64_t authority;
    uint8_t caps[16], attribute;
    if (!cred || kernel_copyout(cred + KERNEL_OFFSET_UCRED_CR_SCEAUTHID,
                                &authority, sizeof(authority)) ||
        kernel_copyout(cred + KERNEL_OFFSET_UCRED_CR_SCECAPS, caps, sizeof(caps)) ||
        kernel_copyout(cred + KERNEL_OFFSET_UCRED_CR_SCEATTRS, &attribute, sizeof(attribute)))
        return EFAULT;
    int full_caps = 1;
    intptr_t prison = kernel_get_ucred_prison(getpid());
    if (!prison || !KERNEL_ADDRESS_PRISON0) return EFAULT;
    for (unsigned i = 0; i < sizeof(caps); ++i)
        if (caps[i] != 0xff) full_caps = 0;
    int open_directories = -1, superuser = -1;
    size_t size = sizeof(open_directories);
    int open_error = sysctlbyname("kern.chroot_allow_open_directories",
                                  &open_directories, &size, NULL, 0) < 0 ? errno : 0;
    if (!open_error && size != sizeof(open_directories)) open_error = EPROTO;
    size = sizeof(superuser);
    int superuser_error = sysctlbyname("security.bsd.suser_enabled",
                                      &superuser, &size, NULL, 0) < 0 ? errno : 0;
    if (!superuser_error && size != sizeof(superuser)) superuser_error = EPROTO;
    ps5log_printf(PS5LOG_MARK,
                  "vfs_prerequisites uid_root=%d euid_root=%d full_caps=%d system_authority=%d attribute80=%d prison0=%d open_dirs=%d open_dirs_error=%d superuser=%d superuser_error=%d",
                  getuid() == 0, geteuid() == 0, full_caps,
                  authority == UINT64_C(0x4801000000000013), !!(attribute & 0x80), prison == KERNEL_ADDRESS_PRISON0,
                  open_error ? -1 : open_directories, open_error,
                  superuser_error ? -1 : superuser, superuser_error);
    return 0;
}

#endif
