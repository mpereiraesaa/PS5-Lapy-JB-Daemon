/* Disposable title used only by the exit-lifetime probe. */
#include "demo_renderer.hpp"

#include <array>
#include <cstdio>
#include <fcntl.h>
#include <span>
#include <unistd.h>

namespace {
std::array<char, 48> banner{"WAITING FOR ROOT PROBE"};

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
        unlink("/download0/etahen_jailbreak");
        int fd = open("/download0/etahen_jailbreak",
                      O_WRONLY | O_CREAT | O_EXCL, 0644);
        if (fd >= 0 && length > 0)
            (void)write(fd, request, static_cast<size_t>(length));
        if (fd >= 0)
            close(fd);
    }
    ps5::demo::run(draw_scene, banner.data());
}
