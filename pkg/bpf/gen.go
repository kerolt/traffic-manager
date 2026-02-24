package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf -cflags "-D__TARGET_ARCH_x86" connect ../../bpf/connect.bpf.c -- -I../../bpf/
