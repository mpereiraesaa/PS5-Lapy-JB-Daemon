# The owned-root backend requires runtime layout validation and a cooperative
# title credential clone before each elevation request.
PYTHON ?= python3
HOST_CC ?= cc
LOGGING_CLIENT ?= ../logging_server/client
TARGET_TITLE ?= PPSA99995
export PS5_PAYLOAD_SDK
export PS5_CXXRT

.PHONY: all owned-service owned-one-shot owned-helper legacy check check-native native-components
all: owned-service

owned-service:
	test -n "$(PS5_PAYLOAD_SDK)"
	$(PYTHON) tools/build_owned_daemon.py --sdk "$(PS5_PAYLOAD_SDK)" --logging-client "$(LOGGING_CLIENT)" --service

owned-one-shot:
	test -n "$(PS5_PAYLOAD_SDK)"
	$(PYTHON) tools/build_owned_daemon.py --sdk "$(PS5_PAYLOAD_SDK)" --logging-client "$(LOGGING_CLIENT)"

owned-helper:
	test -n "$(PS5_PAYLOAD_SDK)"
	$(PYTHON) tools/build_owned_daemon.py --sdk "$(PS5_PAYLOAD_SDK)" --logging-client "$(LOGGING_CLIENT)" --elf-helper --title "$(TARGET_TITLE)"

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
	$(HOST_CC) -std=c11 -Wall -Wextra -Werror -g -fsanitize=address,undefined -Isource source/root_references.c tests/test_root_references.c -o build/host/test_root_references
	./build/host/test_root_references
	$(HOST_CC) -std=c11 -Wall -Wextra -Werror -g -fsanitize=address,undefined -Isource source/donor_transaction.c tests/test_donor_transaction.c -o build/host/test_donor_transaction
	./build/host/test_donor_transaction
	$(HOST_CC) -std=c11 -Wall -Wextra -Werror -g -fsanitize=address,undefined -Isource source/filedesc_refcount.c tests/test_filedesc_refcount.c -o build/host/test_filedesc_refcount
	./build/host/test_filedesc_refcount
	$(HOST_CC) -std=c11 -Wall -Wextra -Werror -g -fsanitize=address,undefined -Isource source/vnode_ref_probe.c tests/test_vnode_ref_probe.c -o build/host/test_vnode_ref_probe
	./build/host/test_vnode_ref_probe

# Compile the transport component only; this is not an elevation payload.
native-components:
	test -n "$(PS5_PAYLOAD_SDK)"
	mkdir -p build/native
	"$(PS5_PAYLOAD_SDK)/bin/prospero-clang" -std=c11 -Wall -Wextra -Werror -O2 -Isource -c source/native_directory.c -o build/native/native_directory.o
