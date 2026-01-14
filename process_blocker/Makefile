# process_blocker专用Makefile
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool

CFLAGS := -g -O2 -Wall
BPF_CFLAGS := -g -O2 -Wall -target bpf -D__TARGET_ARCH_x86

# 包含libbpf头文件
LIBBPF_INCLUDE = ../libbpf/include
LIBBPF_SRC = ../libbpf/src

all: process_blocker

.PHONY: clean
clean:
	rm -f process_blocker *.o *.skel.h

# 生成vmlinux.h
vmlinux.h:
	@if [ -f /sys/kernel/btf/vmlinux ]; then \
		echo "生成vmlinux.h..."; \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h; \
	else \
		echo "错误: 内核不支持BTF"; \
		exit 1; \
	fi

# 构建用户空间程序
process_blocker: process_blocker.c process_blocker.skel.h vmlinux.h
	$(CC) $(CFLAGS) -I$(LIBBPF_INCLUDE) -I$(LIBBPF_SRC)/root \
		-I. -o $@ $< \
		$(LIBBPF_SRC)/libbpf.a -lelf -lz

# 生成骨架头文件
%.skel.h: %.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

# 编译BPF程序
%.bpf.o: %.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) \
		-I$(LIBBPF_INCLUDE) \
		-I. \
		-c $< -o $@
	$(LLVM_STRIP) -g $@

# 运行程序
run: process_blocker
	sudo ./process_blocker
