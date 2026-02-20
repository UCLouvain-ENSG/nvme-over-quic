# SPDX-License-Identifier: BSD-3-Clause
# Makefile for eBPF SO_REUSEPORT program

CLANG ?= clang
LLC ?= llc
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# eBPF target
BPF_TARGET = reuseport_kern.o

# Source files
BPF_SRC = reuseport_kern.c

# Include paths
INCLUDES = -I/usr/include -I/usr/include/bpf

# Compiler flags for eBPF
BPF_CFLAGS = -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES)

.PHONY: all clean install

all: $(BPF_TARGET)

$(BPF_TARGET): $(BPF_SRC)
	@echo "  Compiling eBPF program: $@"
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

clean:
	@echo "  Cleaning eBPF objects"
	rm -f $(BPF_TARGET)

# Optional: Install to a system location
install: $(BPF_TARGET)
	@echo "  Installing eBPF program to $(DESTDIR)/usr/lib/spdk/ebpf/"
	@mkdir -p $(DESTDIR)/usr/lib/spdk/ebpf
	@cp $(BPF_TARGET) $(DESTDIR)/usr/lib/spdk/ebpf/

# Help target
help:
	@echo "eBPF SO_REUSEPORT Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all      - Build eBPF program (default)"
	@echo "  clean    - Remove built objects"
	@echo "  install  - Install to system location"
	@echo ""
	@echo "Usage:"
	@echo "  make"
	@echo "  make clean"
	@echo "  make CLANG=clang-18"
