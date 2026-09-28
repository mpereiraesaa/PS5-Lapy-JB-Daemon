# A native reference-safe backend is not available yet. The inherited ELF is
# never treated as the output of a successful new build.
PYTHON ?= python3
export PS5_PAYLOAD_SDK
export PS5_CXXRT

.PHONY: all legacy check
all:
	@echo 'Native reference-safe elevation unavailable; see docs/ELEVATION.md.' >&2
	@echo 'For an offline legacy comparison build only: make legacy.' >&2
	@exit 1

legacy:
	$(PYTHON) tools/build.py --legacy --fetch-deps

check:
	$(PYTHON) -m unittest discover -s tests -v
	git diff --check
