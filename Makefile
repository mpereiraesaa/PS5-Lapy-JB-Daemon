# A native reference-safe backend is not available yet. The inherited ELF is
# never treated as the output of a successful new build.
PYTHON ?= python3
HOST_CC ?= cc
export PS5_PAYLOAD_SDK
export PS5_CXXRT

.PHONY: all legacy check check-native native-components
all:
	@echo 'Native reference-safe elevation unavailable; see docs/ELEVATION.md.' >&2
	@echo 'For an offline legacy comparison build only: make legacy.' >&2
	@exit 1

legacy:
	$(PYTHON) tools/build.py --legacy --fetch-deps

check: check-native
	$(PYTHON) -m unittest discover -s tests -v
	git diff --check

check-native:
	mkdir -p build/host
	$(HOST_CC) -std=c11 -Wall -Wextra -Werror -g -fsanitize=address,undefined -Isource source/native_directory.c tests/test_native_directory.c -o build/host/test_native_directory
	./build/host/test_native_directory
	$(HOST_CC) -std=c11 -Wall -Wextra -Werror -g -fsanitize=address,undefined -Isource source/sony_scope.c tests/test_sony_scope.c -o build/host/test_sony_scope
	./build/host/test_sony_scope

# Compile the transport component only; this is not an elevation payload.
native-components:
	test -n "$(PS5_PAYLOAD_SDK)"
	mkdir -p build/native
	"$(PS5_PAYLOAD_SDK)/bin/prospero-clang" -std=c11 -Wall -Wextra -Werror -O2 -Isource -c source/native_directory.c -o build/native/native_directory.o
