package bpf

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type Program struct {
	connectObj       connectObjects
	connectCgroup    link.Link
	udpSendmsgCgroup link.Link
	udpRecvmsgCgroup link.Link
	backEndSet       map[int]bool
	freeBackendIDs   []int
	currentIndex     int
}

// DetectCgroupPath 自动检测 cgroup2 的挂载路径
// 返回 cgroup2 在当前系统中的挂载点，如果未挂载则返回错误
func DetectCgroupPath() (string, error) {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		// 示例格式: cgroup2 /sys/fs/cgroup/unified cgroup2 rw,nosuid,nodev,noexec,relatime 0 0
		fields := strings.Split(scanner.Text(), " ")
		if len(fields) >= 3 && fields[2] == "cgroup2" {
			return fields[1], nil
		}
	}

	return "", fmt.Errorf("cgroup2 not mounted")
}

// LoadProgram 加载 eBPF 程序和 Maps 到内核
// 包括调整 rlimit 内存锁定限制、创建 Map Pin 路径
func LoadProgram() (Program, error) {
	var program Program
	var options ebpf.CollectionOptions
	options.Maps.PinPath = MapsPinPath

	// 1. 解除内存锁定限制 (RLIMIT_MEMLOCK), 允许当前进程加载 eBPF 程序
	err := rlimit.RemoveMemlock()
	if err != nil {
		slog.Error("Setting limit failed", "error", err)
		return Program{}, fmt.Errorf("setting limit failed: %s", err)
	}

	// 2. 创建 Map 固化路径 (Pin Path)
	err = os.Mkdir(MapsPinPath, os.ModePerm)
	if err != nil {
		// 如果已存在则忽略错误
	}

	// 3. 加载 eBPF 对象 (包含 Maps 和 Program)
	err = loadConnectObjects(&program.connectObj, &options)
	if err != nil {
		return Program{}, fmt.Errorf("error load objects: %s\n", err)
	}

	program.backEndSet = make(map[int]bool)
	program.freeBackendIDs = make([]int, 0)
	program.currentIndex = 0

	return program, err
}

// Attach 将 eBPF 程序挂载到 cgroup 的 connect4/sendmsg4/recvmsg4 钩子上。
// TCP 只走 connect4，UDP 只走 sendmsg4/recvmsg4，避免 connected UDP 被两条路径重复改写。
func (p *Program) Attach() error {
	slog.Info("Socket redirect started!")

	cgroupPath, err := DetectCgroupPath()
	if err != nil {
		return fmt.Errorf("detect cgroup path failed: %s", err)
	}

	p.connectCgroup, err = link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: p.connectObj.connectPrograms.Sock4Connect,
	})
	if err != nil {
		return fmt.Errorf("error attaching connect to cgroup: %s", err)
	}

	p.udpSendmsgCgroup, err = link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupUDP4Sendmsg,
		Program: p.connectObj.connectPrograms.Sock4Sendmsg,
	})
	if err != nil {
		_ = p.connectCgroup.Close()
		p.connectCgroup = nil
		return fmt.Errorf("error attaching udp sendmsg to cgroup: %s", err)
	}

	p.udpRecvmsgCgroup, err = link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupUDP4Recvmsg,
		Program: p.connectObj.connectPrograms.Sock4Recvmsg,
	})
	if err != nil {
		_ = p.udpSendmsgCgroup.Close()
		p.udpSendmsgCgroup = nil
		_ = p.connectCgroup.Close()
		p.connectCgroup = nil
		return fmt.Errorf("error attaching udp recvmsg to cgroup: %s", err)
	}

	return nil
}

// Close 卸载程序并清理资源
// 即使程序退出，Pin 住的 Map 依然会保留在文件系统中，直到被显式删除
func (p *Program) Close() {
	slog.Info("Exiting...")

	if p.connectCgroup != nil {
		slog.Info("Closing connect cgroup...")
		_ = p.connectCgroup.Close()
	}

	if p.udpSendmsgCgroup != nil {
		slog.Info("Closing udp sendmsg cgroup...")
		_ = p.udpSendmsgCgroup.Close()
	}

	if p.udpRecvmsgCgroup != nil {
		slog.Info("Closing udp recvmsg cgroup...")
		_ = p.udpRecvmsgCgroup.Close()
	}

	if p.connectObj.connectMaps.ServiceMetaMap != nil {
		_ = p.connectObj.connectMaps.ServiceMetaMap.Unpin()
		_ = p.connectObj.connectMaps.ServiceMetaMap.Close()
		slog.Info("Unpin and close service meta map")
	}

	if p.connectObj.connectMaps.ServiceSlotMap != nil {
		_ = p.connectObj.connectMaps.ServiceSlotMap.Unpin()
		_ = p.connectObj.connectMaps.ServiceSlotMap.Close()
		slog.Info("Unpin and close service slot map")
	}

	if p.connectObj.connectMaps.BackendMap != nil {
		_ = p.connectObj.connectMaps.BackendMap.Unpin()
		_ = p.connectObj.connectMaps.BackendMap.Close()
		slog.Info("Unpin and close backend map")
	}

	if p.connectObj.connectMaps.StatsMap != nil {
		_ = p.connectObj.connectMaps.StatsMap.Unpin()
		_ = p.connectObj.connectMaps.StatsMap.Close()
		slog.Info("Unpin and close stats map")
	}

	if p.connectObj.connectMaps.UdpAffinityMap != nil {
		_ = p.connectObj.connectMaps.UdpAffinityMap.Unpin()
		_ = p.connectObj.connectMaps.UdpAffinityMap.Close()
		slog.Info("Unpin and close udp affinity map")
	}

	if p.connectObj.connectMaps.NatSkMap != nil {
		_ = p.connectObj.connectMaps.NatSkMap.Unpin()
		_ = p.connectObj.connectMaps.NatSkMap.Close()
		slog.Info("Unpin and close nat sk map")
	}

	err := os.Remove(MapsPinPath)
	if err != nil {
		slog.Warn("Remove map pin file path failed", "path", MapsPinPath, "error", err)
	}
}
