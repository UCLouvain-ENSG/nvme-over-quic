#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (C) 2025 Intel Corporation.
#  All rights reserved.
#

SPDK_ROOT_DIR := $(abspath $(CURDIR)/..)
include $(SPDK_ROOT_DIR)/mk/spdk.common.mk

.PHONY: all clean install

ifneq ($(Q),)
REDIRECT=> /dev/null
endif

QUICLY_DIR=$(SPDK_ROOT_DIR)/quicly

all:
	@echo "Building quicly with CMake..."
	$(Q)cd $(QUICLY_DIR) && \
		if [ ! -f Makefile ]; then \
			cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_POSITION_INDEPENDENT_CODE=ON . $(REDIRECT); \
		fi
	$(Q)$(MAKE) -C $(QUICLY_DIR) $(REDIRECT)

install: all
	@echo "quicly install not needed (static linking)"

uninstall:
	@echo "quicly uninstall not needed"

clean:
	$(Q)if [ -f $(QUICLY_DIR)/Makefile ]; then \
		$(MAKE) -C $(QUICLY_DIR) clean $(REDIRECT); \
	fi
	$(Q)cd $(QUICLY_DIR) && rm -rf CMakeFiles CMakeCache.txt Makefile cmake_install.cmake
