CLANG ?= /home/it1/.local/bin/clang
LIBBPF_DIR ?= /home/it1/research/tsn-project/repos/xdp-tutorial/lib/libbpf/src

CFLAGS := -O2 -g -Wall -target bpf
CFLAGS += -I$(LIBBPF_DIR) -I/usr/include/x86_64-linux-gnu -I/home/it1/local/usr/include

all: xdp_psfp_kern.o

xdp_psfp_kern.o: xdp_psfp_kern.c common.h
	$(CLANG) $(CFLAGS) -c $< -o $@

clean:
	rm -f xdp_psfp_kern.o
