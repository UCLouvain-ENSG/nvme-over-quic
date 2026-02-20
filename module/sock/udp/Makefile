SPDK_ROOT_DIR := $(abspath $(CURDIR)/../../..)
include $(SPDK_ROOT_DIR)/mk/spdk.common.mk

SO_VER := 5
SO_MINOR := 0

C_SRCS = udp.c
LIBNAME = sock_udp
LOCAL_SYS_LIBS =

# Add eBPF support if enabled
ifeq ($(CONFIG_EBPF),y)
CFLAGS += -DSPDK_CONFIG_EBPF
LOCAL_SYS_LIBS += -lbpf
# Build eBPF program
EBPF_DIR = $(CURDIR)/ebpf
EBPF_TARGET = $(EBPF_DIR)/reuseport_kern.o
$(EBPF_TARGET):
	$(Q)$(MAKE) -C $(EBPF_DIR)
all: $(EBPF_TARGET)
endif

SPDK_MAP_FILE = $(SPDK_ROOT_DIR)/mk/spdk_blank.map

include $(SPDK_ROOT_DIR)/mk/spdk.lib.mk