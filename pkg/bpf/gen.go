package bpf

//go:generate go tool bpf2go -tags linux -target bpfel connect ../../bpf/cgroup_sock.c -- -I../../bpf/
