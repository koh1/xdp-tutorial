# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

XDP_TARGETS := xdp_pass_kern
USER_TARGETS := xdp_pass_user

LLC ?= llc-8
CLANG ?= clang-8
CC := gcc

LIBBPF_DIR = ../libbpf/src/
COMMON_DIR = ../common/

include $(COMMON_DIR)/common.mk
COMMON_OBJS := $(COMMON_DIR)/common_params.o
