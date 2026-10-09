/* Disposable title used only by the exit-lifetime probe. */
#include "demo_renderer.hpp"

#include <array>
#include <cstdio>
#include <fcntl.h>
#include <span>
#include <unistd.h>

namespace {
std::array<char, 48> banner{"WAITING FOR ROOT PROBE"};

#ifdef LAPY_OWNED_RACE_TARGET
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
    if (seteuid(geteuid()) == 0) {
        char request[64];
        int length = std::snprintf(request, sizeof(request),
                                   "{\"PID\":%d}\n", getpid());
        unlink(request_path);
        int fd = open(request_path,
                      O_WRONLY | O_CREAT | O_EXCL, 0644);
        if (fd >= 0 && length > 0)
            (void)write(fd, request, static_cast<size_t>(length));
        if (fd >= 0)
            close(fd);
    }
#ifdef LAPY_OWNED_RACE_TARGET
    usleep(500000);
    return 0;
#endif
    ps5::demo::run(draw_scene, banner.data());
}
