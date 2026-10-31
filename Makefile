# ============================================================
#  授权网络暴露面巡检工具 —— 构建脚本 (Makefile)
#  基础项目: 现有 TCP 半连接端口扫描器 (C + GTK3)
# ------------------------------------------------------------
#  依赖库: GTK3 / libpcap / libnet / pthread
#          SQLite3 已内置，无需系统安装
#  构建:   make            生成可执行文件 tcp_scanner
#  清理:   make clean      删除中间目标文件与可执行文件
#  检查:   make check      检查所需库是否安装
# ============================================================

TARGET := tcp_scanner
SRCDIR := src
INCDIR := include
BUILDDIR := build

CC   ?= gcc
CSTD := -std=gnu11
WARN := -Wall -Wextra
OPT  ?= -O2 -g

# ----------------------------------------------------------
#  GTK3 编译/链接参数
# ----------------------------------------------------------
GTK_CFLAGS := $(shell pkg-config --cflags gtk+-3.0 2>/dev/null)
GTK_LIBS   := $(shell pkg-config --libs   gtk+-3.0 2>/dev/null)
ifeq ($(strip $(GTK_CFLAGS)),)
$(error ❌ 未找到 GTK3 开发包。请安装: sudo apt install libgtk-3-dev)
endif
ifeq ($(strip $(GTK_LIBS)),)
$(error ❌ 未找到 GTK3 链接库。请安装: sudo apt install libgtk-3-dev)
endif

# ----------------------------------------------------------
#  libpcap
# ----------------------------------------------------------
PCAP_CFLAGS := $(shell pkg-config --cflags libpcap 2>/dev/null)
PCAP_LIBS   := $(shell pkg-config --libs   libpcap 2>/dev/null)
ifeq ($(strip $(PCAP_LIBS)),)
PCAP_LIBS := -lpcap
endif

# ----------------------------------------------------------
#  libnet (优先 pkg-config, 其次 libnet-config, 否则 -lnet)
# ----------------------------------------------------------
LIBNET_CFLAGS := $(shell pkg-config --cflags libnet 2>/dev/null)
LIBNET_LIBS   := $(shell pkg-config --libs   libnet 2>/dev/null)
ifeq ($(strip $(LIBNET_CFLAGS)),)
LIBNET_CFLAGS := $(shell libnet-config --cflags 2>/dev/null)
endif
ifeq ($(strip $(LIBNET_LIBS)),)
LIBNET_LIBS := $(shell libnet-config --libs 2>/dev/null)
endif
ifeq ($(strip $(LIBNET_LIBS)),)
LIBNET_LIBS := -lnet
endif

# 依赖在非标准路径时:
#   make EXTRA_CFLAGS=-I/自定义/include EXTRA_LIBS=-L/自定义/lib
EXTRA_CFLAGS ?=
EXTRA_LIBS   ?=

CFLAGS := $(CSTD) $(WARN) $(OPT) -pthread -I$(INCDIR) -I$(SRCDIR) \
          $(GTK_CFLAGS) $(PCAP_CFLAGS) $(LIBNET_CFLAGS) $(EXTRA_CFLAGS)
LDLIBS := $(GTK_LIBS) $(PCAP_LIBS) $(LIBNET_LIBS) -lpthread $(EXTRA_LIBS)

SRCS := \
          $(SRCDIR)/main.c \
          $(SRCDIR)/app/gui.c \
          $(SRCDIR)/ui/pages/page_devices.c \
          $(SRCDIR)/ui/pages/page_policies.c \
          $(SRCDIR)/ui/pages/page_scan.c \
          $(SRCDIR)/ui/pages/page_records.c \
          $(SRCDIR)/ui/export_dialog.c \
          $(SRCDIR)/services/scan_service.c \
          $(SRCDIR)/services/device_service.c \
          $(SRCDIR)/services/policy_service.c \
          $(SRCDIR)/data/export.c \
          $(SRCDIR)/data/db.c \
          $(SRCDIR)/data/csv.c \
          $(SRCDIR)/core/scanner.c \
          $(SRCDIR)/domain.c \
          $(SRCDIR)/data/sqlite3.c

OBJS := $(patsubst $(SRCDIR)/%.c,$(BUILDDIR)/%.o,$(SRCS))

.PHONY: all clean run check

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDLIBS)

$(BUILDDIR):
	mkdir -p $@

$(BUILDDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

# sqlite3.c 是第三方合并版，关掉 Warning 避免噪音，开启线程安全
$(BUILDDIR)/data/sqlite3.o: CFLAGS += -w -DSQLITE_THREADSAFE=1 -DSQLITE_OMIT_LOAD_EXTENSION

clean:
	rm -f $(OBJS) $(OBJS:.o=.d) $(BUILDDIR)/services_test $(TARGET)

run: $(TARGET)
	./$(TARGET)

check:
	@echo "GTK3:      $$(pkg-config --modversion gtk+-3.0 2>/dev/null || echo 缺失)"
	@echo "libpcap:   $$(pkg-config --modversion libpcap   2>/dev/null || echo 可能在系统路径)"
	@echo "libnet:    $$(pkg-config --modversion libnet    2>/dev/null || libnet-config --version 2>/dev/null || echo 可能在系统路径)"
	@echo "SQLite3:   已内置 (src/data/sqlite3.c, 无需系统包)"
	@echo "---"
	@echo "CFLAGS:    $(CFLAGS)"
	@echo "LDLIBS:    $(LDLIBS)"
	@echo "---"
	@echo "✅ 依赖检查通过"

-include $(OBJS:.o=.d)

