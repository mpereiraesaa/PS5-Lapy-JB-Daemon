/* Disposable title used only by the exit-lifetime probe. */
#include "demo_renderer.hpp"

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <span>
#include <unistd.h>

namespace {
std::array<char, 48> banner{"WAITING FOR ROOT PROBE"};

#if defined(LAPY_OWNED_RACE_TARGET) || defined(LAPY_OWNED_ONE_SHOT_TARGET)
constexpr const char *request_path = "/download0/elevate_proc";
#else
constexpr const char *request_path = "/download0/etahen_jailbreak";
#endif

void draw_scene(ps5::demo::Canvas &canvas) noexcept
{
    using ps5::demo::Color;
    canvas.clear(Color::background);
    canvas.text(120, 90, "LAPY EXIT-LIFETIME TARGET", 8, Color::white);
    canvas.text(120, 245, banner.data(), 5, Color::cyan);
}
}

int main()
{
#ifdef LAPY_OWNED_ONE_SHOT_TARGET
    int result_fd = open("/download0/lapy_owned_result",
                         O_WRONLY | O_CREAT | O_TRUNC, 0644);
#endif
    int request_written = 0;
    if (seteuid(geteuid()) == 0) {
        char request[64];
#ifdef LAPY_WRONG_PID_TARGET
        int requested_pid = 2;
#else
        int requested_pid = getpid();
#endif
        int length = std::snprintf(request, sizeof(request),
                                   "{\"PID\":%d}\n", requested_pid);
        unlink(request_path);
        int fd = open(request_path,
                      O_WRONLY | O_CREAT | O_EXCL, 0644);
        if (fd >= 0 && length > 0)
            request_written = write(fd, request, static_cast<size_t>(length)) == length;
        if (fd >= 0)
            close(fd);
    }
#ifdef LAPY_OWNED_RACE_TARGET
    usleep(500000);
    return 0;
#elif defined(LAPY_OWNED_ONE_SHOT_TARGET)
    int acknowledged = 0;
    if (request_written && result_fd >= 0) {
        for (unsigned i = 0; i < 200; ++i) {
            if (access(request_path, F_OK) && errno == ENOENT) {
                acknowledged = 1;
                break;
            }
            usleep(50000);
        }
    }
    int data_ok = 0;
    int open_errno = acknowledged ? 0 : ETIMEDOUT;
    if (acknowledged) {
        char path[80];
        std::snprintf(path, sizeof(path), "/data/lapy_one_shot_%d", getpid());
        errno = 0;
        int fd = open(path, O_RDWR | O_CREAT | O_EXCL, 0600);
        open_errno = errno;
        if (fd >= 0) {
            const char token[] = "LAPYOWN\n";
            char check[sizeof(token)] = {};
            data_ok = write(fd, token, sizeof(token) - 1) == sizeof(token) - 1 &&
                      lseek(fd, 0, SEEK_SET) == 0 &&
                      read(fd, check, sizeof(token) - 1) == sizeof(token) - 1 &&
                      !std::memcmp(check, token, sizeof(token) - 1);
            close(fd);
            unlink(path);
        }
    }
    if (result_fd >= 0) {
        char result[80];
        int length = std::snprintf(result, sizeof(result),
                                   "DATA_OK=%d OPEN_ERRNO=%d\n",
                                   data_ok, open_errno);
        if (length > 0)
            (void)write(result_fd, result, static_cast<size_t>(length));
        close(result_fd);
    }
    return data_ok ? 0 : 1;
#endif
    ps5::demo::run(draw_scene, banner.data());
}
