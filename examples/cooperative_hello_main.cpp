/* Cooperative FW12.02 test title for ps5-native-app-boilerplate.
 * This is only the app main source; obtain the boilerplate and ps5log/1
 * client separately. The deployed test binary was temporary and restored.
 */
#define PS5LOG_IMPLEMENTATION
#include "ps5log.h"
#include "demo_renderer.hpp"
#include <array>
#include <span>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {
std::array<char, 48> banner{};
void draw_scene(ps5::demo::Canvas &canvas) noexcept {
    using ps5::demo::Color;
    canvas.clear(Color::background);
    canvas.text(120, 90, "LAPY COOPERATIVE TEST", 10, Color::white);
    canvas.text(120, 245, banner.data(), 5, Color::cyan);
}
}

int main() {
    int log_init = ps5log_init_default("PPSA99994", "lapy-cooperative-hello");
    ps5log_printf(PS5LOG_MARK, "coop_start pid=%d uid=%u euid=%u", getpid(),
                  static_cast<unsigned>(getuid()), static_cast<unsigned>(geteuid()));
    int result_fd = open("/download0/lapy_owned_result", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (result_fd >= 0) fchmod(result_fd, 0644);
    errno = 0;
    int clone_result = seteuid(geteuid());
    int clone_errno = errno;
    ps5log_printf(clone_result ? PS5LOG_ERR : PS5LOG_MARK,
                  "credential_clone result=%d errno=%d uid=%u euid=%u",
                  clone_result, clone_errno, static_cast<unsigned>(getuid()),
                  static_cast<unsigned>(geteuid()));
    if (clone_result == 0 && result_fd >= 0) {
        char marker[80];
        int length = snprintf(marker, sizeof(marker), "{\"PID\":%d,\"LogInit\":%d,\"Clone\":%d,\"ResultFD\":%d}\n", getpid(), log_init, clone_result, result_fd >= 0);
        unlink("/download0/elevate_proc");
        int fd = open("/download0/elevate_proc", O_WRONLY | O_CREAT | O_EXCL, 0644);
        if (fd >= 0) fchmod(fd, 0644);
        int write_result = fd >= 0 && length > 0 &&
                           write(fd, marker, static_cast<size_t>(length)) == length;
        int write_errno = errno;
        if (fd >= 0) close(fd);
        ps5log_printf(write_result ? PS5LOG_MARK : PS5LOG_ERR,
                      "request_written ok=%d errno=%d", write_result, write_errno);
        if (write_result) {
            int acknowledged = 0;
            for (int i = 0; i < 200; ++i) {
                if (access("/download0/elevate_proc", F_OK) != 0 && errno == ENOENT) {
                    acknowledged = 1;
                    break;
                }
                usleep(50000);
            }
            ps5log_printf(PS5LOG_MARK, "request_acknowledged ok=%d", acknowledged);
            if (acknowledged) {
                char path[96];
                snprintf(path, sizeof(path), "/data/lapy_owned_root_%d", getpid());
                int data_fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
                int data_errno = errno;
                int data_rw = 0;
                if (data_fd >= 0) {
                    const char token[] = "LAPYOWN\n";
                    data_rw = write(data_fd, token, sizeof(token) - 1) == sizeof(token) - 1;
                    close(data_fd);
                    if (data_rw) {
                        data_fd = open(path, O_RDONLY);
                        char check[sizeof(token)] = {};
                        data_rw = data_fd >= 0 &&
                                  read(data_fd, check, sizeof(token) - 1) == sizeof(token) - 1 &&
                                  memcmp(check, token, sizeof(token) - 1) == 0;
                        if (data_fd >= 0) close(data_fd);
                    }
                    unlink(path);
                }
                ps5log_printf(data_rw ? PS5LOG_MARK : PS5LOG_ERR,
                              "data_rw_pass ok=%d open_errno=%d", data_rw, data_errno);
                if (result_fd >= 0) {
                    char result[96];
                    int result_len = snprintf(result, sizeof(result), "DATA_OK=%d OPEN_ERRNO=%d\n", data_rw, data_errno);
                    if (result_len > 0) write(result_fd, result, static_cast<size_t>(result_len));
                    close(result_fd);
                    result_fd = -1;
                }
            }
        }
    }
    if (result_fd >= 0) close(result_fd);
    ps5log_close("coop-test-finished");
    ps5::demo::read_asset_text("/app0/assets/banner.txt", std::span{banner}, "LAPY TEST");
    ps5::demo::run(draw_scene, banner.data());
}
