/* Call this in the process needing /data, before creating other threads.
 * A successful return publishes the request; it is not an elevation ack.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

int lapy_request_elevation(void)
{
    const char *request = "/download0/elevate_proc";
    char temporary[80];
    char body[64];
    int fd;
    int body_length, temp_length;

    /* The native same-UID path gives this process a private ucred. */
    if (seteuid(geteuid()) != 0)
        return -1;

    body_length = snprintf(body, sizeof(body), "{\"PID\":%ld}\n", (long)getpid());
    if (body_length <= 0 || (size_t)body_length >= sizeof(body)) {
        errno = EOVERFLOW;
        return -1;
    }
    temp_length = snprintf(temporary, sizeof(temporary),
                      "/download0/.elevate_proc.%ld", (long)getpid());
    if (temp_length <= 0 || (size_t)temp_length >= sizeof(temporary)) {
        errno = EOVERFLOW;
        return -1;
    }
    fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (fd < 0)
        return -1;
    if (write(fd, body, (size_t)body_length) != body_length) {
        int saved = errno ? errno : EIO;
        close(fd);
        unlink(temporary);
        errno = saved;
        return -1;
    }
    if (close(fd) != 0) {
        int saved = errno;
        unlink(temporary);
        errno = saved;
        return -1;
    }
    /* The daemon sees only a complete JSON request. */
    if (rename(temporary, request) != 0) {
        int saved = errno;
        unlink(temporary);
        errno = saved;
        return -1;
    }
    return 0;
}

/* Wait for daemon consumption and verify /data access before proceeding.
 * The complete test title is in cooperative_hello_main.cpp.
 */
