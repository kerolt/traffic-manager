package bpf

import (
	"bufio"
	"fmt"
	"log/slog"
	"math"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/u8proto"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const MapsPinPath = "/sys/fs/bpf/sock_ops_map"

type Program struct {
	connectObj    connectObjects
	connectCgroup link.Link
	backEndSet    map[int]bool
	currentIndex  int
}

// Service 定义服务配置结构
// 用于外部传入服务信息
type Service struct {
	IP          string
	Port        string
	Possibility float64
}

// Backend 定义后端配置结构
// 用于外部传入后端节点信息
// 注意与 bpf/type.go 中的 BackendValue (BPF Map Value) 区分
type Backend struct {
	IP          string
	Port        string
	Possibility float64
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
		// slog.Info("Mkdir failed (expected if exists)", "error", err)
	}

	// 3. 加载 eBPF 对象 (包含 Maps 和 Program)
	err = loadConnectObjects(&program.connectObj, &options)
	if err != nil {
		return Program{}, fmt.Errorf("error load objects: %s\n", err)
	}

	program.backEndSet = make(map[int]bool)
	program.currentIndex = 0

	return program, err
}

// Attach 将 eBPF 程序挂载到 cgroup 的 connect4 钩子上
// 自此，该 cgroup 下的所有 IPv4 TCP 连接都将被此程序拦截
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

	return nil
}

// Close 卸载程序并清理资源
// 即使程序退出，Pin 住的 Map 依然会保留在文件系统中，直到被显式删除
func (p *Program) Close() {
	slog.Info("Exiting...")

	if p.connectCgroup != nil {
		slog.Info("Closing connect cgroup...")
		p.connectCgroup.Close()
	}

	if p.connectObj.connectMaps.ServicesMap != nil {
		p.connectObj.connectMaps.ServicesMap.Unpin()
		p.connectObj.connectMaps.ServicesMap.Close()
		slog.Info("Unpin and close service map")
	}

	if p.connectObj.connectMaps.BackendMap != nil {
		p.connectObj.connectMaps.BackendMap.Unpin()
		p.connectObj.connectMaps.BackendMap.Close()
		slog.Info("Unpin and close backend map")
	}

	err := os.Remove(MapsPinPath)
	if err != nil {
		slog.Warn("Remove map pin file path failed", "path", MapsPinPath, "error", err)
	}
}

// InsertServiceItem 将服务元数据插入 Service Map
func (p *Program) InsertServiceItem(serviceIP string, servicePort string, backendNumber int, action Action) bool {
	servicePortInt, err := strconv.Atoi(servicePort)
	if err != nil {
		slog.Error("InsertServiceItem: servicePort parse failed", "error", err)
		return false
	}

	serviceKey := NewServiceKey(net.ParseIP(serviceIP), uint16(servicePortInt), u8proto.ANY, 0, 0)
	// 使用 Slot=0 表示这是服务本身的配置条目，而非具体的后端槽位
	serviceValue := NewServiceEntry(BackendId{0}, uint16(backendNumber), Possibility{0, 0}, action)
	err = p.connectObj.connectMaps.ServicesMap.Update(serviceKey.ToNetwork(), serviceValue.ToNetwork(), ebpf.UpdateAny)
	if err != nil {
		slog.Error("InsertServiceItem: connectObj.connectMaps.ServicesMap.Update failed", "error", err)
		return false
	}

	slog.Info("InsertServiceItem succeeded", "serviceIP", serviceIP, "servicePort", servicePortInt, "backendNumber", backendNumber)
	return true
}

// DeleteServiceItem 从 Service Map 删除服务或后端槽位
// 当 slotIndex = 0 时删除服务本身
func (p *Program) DeleteServiceItem(serviceIP string, servicePort int, slotIndex int) bool {
	serviceKey := NewServiceKey(net.ParseIP(serviceIP), uint16(servicePort), u8proto.ANY, 0, uint16(slotIndex))
	err := p.connectObj.connectMaps.ServicesMap.Delete(serviceKey.ToNetwork())
	if err != nil {
		slog.Error("DeleteServiceItem: connectObj.connectMaps.ServicesMap.Delete failed", "error", err)
		return false
	}
	slog.Info("DeleteServiceItem succeeded", "serviceIP", serviceIP, "servicePort", servicePort, "slotIndex", slotIndex)
	return true
}

// InsertBackendItem 将后端信息插入 Service Map (作为槽位) 和 Backend Map (作为详细信息)
func (p *Program) InsertBackendItem(serviceIP string, servicePort int, backendIP string, backendPort int, backendID int, slotIndex int, possibility float64, possibilityUpperBound float64) bool {
	// 构造后端 ID,用于将 Map 中的两个层级关联起来
	backendKey := BackendId{uint32(backendID)}
	backendServiceKey := NewServiceKey(net.ParseIP(serviceIP), uint16(servicePort), u8proto.ANY, 0, uint16(slotIndex))

	// 在 Service Map 中插入后端槽位信息 (包含权重和 ID 引用)
	backendServiceValue := NewServiceEntry(backendKey, 0, Possibility{possibility, possibilityUpperBound}, DefaultAction)
	err := p.connectObj.connectMaps.ServicesMap.Update(backendServiceKey.ToNetwork(), backendServiceValue.ToNetwork(), ebpf.UpdateAny)
	if err != nil {
		slog.Error("InsertBackendItem: connectObj.connectMaps.ServicesMap.Update failed", "error", err)
		return false
	}

	// 在 Backend Map 中插入实际的物理地址信息
	backendValue := NewBackendValue(net.ParseIP(backendIP), uint16(backendPort), u8proto.ANY, loadbalancer.BackendStateActive)
	err = p.connectObj.connectMaps.BackendMap.Update(backendKey.ID, backendValue.ToNetwork(), ebpf.UpdateAny)
	if err != nil {
		slog.Error("InsertBackendItem: connectObj.connectMaps.BackendMap.Update failed", "error", err)
		return false
	}
	slog.Info("InsertBackendItem succeeded", "serviceIP", serviceIP, "servicePort", servicePort, "backendID", backendID, "slotIndex", slotIndex, "possibility", possibility)
	return true
}

// DeleteBackendItem 根据全局 BackendID 从 Backend Map 删除条目
func (p *Program) DeleteBackendItem(backendID int) bool {
	// 注意: Map Key 是 uint32 类型
	err := p.connectObj.connectMaps.BackendMap.Delete(uint32(backendID))
	if err != nil {
		slog.Error("DeleteBackendItem: connectObj.connectMaps.BackendMap.Delete Delete", "error", err)
		return false
	}
	slog.Info("DeleteBackendItem succeeded", "backendID", backendID)
	return true
}

// AutoInsertService 自动编排并插入完整的服务及其所属的后端列表
func (p *Program) AutoInsertService(service Service, backendList []Backend, action Action, affiliatedServiceList []Service) {
	// 如果不是重定向动作,则忽略级联服务列表
	if action != RedirectAction {
		affiliatedServiceList = nil
	}

	totalPercentage := 0.0
	// 1. 插入服务元数据 (槽位 0)
	p.InsertServiceItem(service.IP, service.Port, len(backendList), action)

	// 2. 遍历并插入普通后端
	for i, backend := range backendList {
		totalPercentage += backend.Possibility
		// 槽位从 1 开始
		p.AutoInsertBackend(service.IP, service.Port, backend.IP, backend.Port, i+1, backend.Possibility, totalPercentage)
	}

	// 3. 遍历并插入级联服务 (作为特殊后端处理)
	for i, affiliatedService := range affiliatedServiceList {
		totalPercentage += affiliatedService.Possibility
		p.AutoInsertBackend(service.IP, service.Port, affiliatedService.IP, affiliatedService.Port, len(backendList)+i+1, affiliatedService.Possibility, totalPercentage)
	}

	if math.Abs(totalPercentage-1) > 0.005 {
		slog.Warn("Total weight for service is not 1", "serviceIP", service.IP, "servicePort", service.Port, "totalPercentage", totalPercentage)
	}
}

// AutoDeleteService 自动删除服务及其关联的所有后端资源
func (p *Program) AutoDeleteService(service Service, affiliatedServiceList []Service) bool {
	serviceIP := service.IP
	servicePort, err := strconv.Atoi(service.Port)
	if err != nil {
		slog.Error("AutoDeleteService: servicePort parse failed", "error", err)
		return false
	}

	// 查询服务元数据以获取后端数量
	serviceKey := NewServiceKey(net.ParseIP(serviceIP), uint16(servicePort), u8proto.ANY, 0, 0)
	serviceValue := NewServiceEntry(BackendId{0}, uint16(0), Possibility{0, 0}, DefaultAction)

	// 注意: 这里使用 Lookup 来获取当前的后端计数
	err = p.connectObj.connectMaps.ServicesMap.Lookup(serviceKey.ToNetwork(), serviceValue)
	if err != nil {
		slog.Error("AutoDeleteService: connectObj.connectMaps.ServicesMap.Lookup failed", "error", err)
		return false
	}
	slog.Debug("To delete service", "serviceKey", serviceKey.String())

	// 先删除服务元数据
	p.DeleteServiceItem(serviceIP, servicePort, 0)

	// 循环删除所有普通后端 (Slot 1 ~ N)
	for i := 1; i <= int(serviceValue.Count); i++ {
		backendServiceKey := NewServiceKey(net.ParseIP(serviceIP), uint16(servicePort), u8proto.ANY, 0, uint16(i))
		backendServiceValue := NewServiceEntry(BackendId{uint32(0)}, 0, Possibility{0, 0}, DefaultAction)

		err := p.connectObj.connectMaps.ServicesMap.Lookup(backendServiceKey.ToNetwork(), backendServiceValue)
		if err != nil {
			slog.Warn("AutoDeleteService: connectObj.connectMaps.ServicesMap.Lookup failed", "error", err)
			break
		}
		slog.Debug("To delete backend service", "backendServiceKey", backendServiceKey.String(), "backendServiceValue", backendServiceValue.String())

		// 删除 Backend Map 中的具体条目
		p.AutoDeleteBackend(int(backendServiceValue.BackendID.ID))
		// 删除 Service Map 中的槽位索引
		p.DeleteServiceItem(serviceIP, servicePort, i)
	}

	// TODO: 处理级联服务的清理逻辑 (目前代码有些混淆,仅作语法适配)
	for i := 0; i < len(affiliatedServiceList); i++ {
		if err != nil {
			slog.Error("AutoDeleteService: servicePort parse failed", "error", err)
			return false
		}
		backendServiceKey := NewServiceKey(net.ParseIP(serviceIP), uint16(servicePort), u8proto.ANY, 0, uint16(int(serviceValue.Count)+i+1))
		backendServiceValue := NewServiceEntry(BackendId{uint32(0)}, 0, Possibility{0, 0}, DefaultAction)
		err = p.connectObj.connectMaps.ServicesMap.Lookup(backendServiceKey.ToNetwork(), backendServiceValue)
		if err != nil {
			slog.Warn("AutoDeleteService: connectObj.connectMaps.ServicesMap.Lookup failed", "error", err)
			break
		}
		slog.Debug("To delete affiliatedService", "backendServiceKey", backendServiceKey.String())
		p.DeleteServiceItem(serviceIP, servicePort, int(serviceValue.Count)+i+1)
		p.AutoDeleteBackend(int(backendServiceValue.BackendID.ID))
	}
	slog.Info("AutoDeleteService succeeded", "serviceIP", serviceIP, "servicePort", servicePort)
	return true
}

// declareBackendID 生成并返回一个递增的后端 ID
// 注意: 这里仅为简单实现，未处理并发安全，生产环境应加锁
func (p *Program) declareBackendID() int {
	backendID := p.currentIndex
	p.currentIndex++
	return backendID
}

// AutoInsertBackend 自动声明 BackendID 并将后端节点插入到 BPF Map
// 参数:
//   - serviceIP, servicePortStr: 服务端的 IP 和端口
//   - backendIP, backendPortStr: 后端 Pod 的 IP 和端口
//   - slotIndex: 该后端在服务后端列表中的槽位索引
//   - possibility, possibilityUpperBound: 负载均衡概率区间
//
// 返回:
//   - bool: 是否插入成功
//   - int: 分配的 backendID
func (p *Program) AutoInsertBackend(serviceIP string, servicePortStr string, backendIP string, backendPortStr string, slotIndex int, possibility float64, possibilityUpperBound float64) (bool, int) {
	// 1. 分配一个新的 Backend ID
	backendID := p.declareBackendID()

	// 2. 解析端口字符串
	servicePort, _ := strconv.Atoi(servicePortStr)
	backendPort, _ := strconv.Atoi(backendPortStr)

	// 3. 调用底层 InsertBackendItem 更新 BPF Maps
	ok := p.InsertBackendItem(serviceIP, servicePort, backendIP, backendPort, backendID, slotIndex, possibility, possibilityUpperBound)
	if ok {
		// 4. 记录在内存中，用于清理
		p.backEndSet[backendID] = true
		slog.Info("AutoInsertBackend succeeded",
			"serviceIP", serviceIP,
			"servicePort", servicePort,
			"backendIP", backendIP,
			"backendPort", backendPort,
			"backendID", backendID,
			"slotIndex", slotIndex,
			"possibility", possibility)
	}
	return ok, backendID
}

// AutoDeleteBackend 从 BPF Map 中删除指定的后端节点
// 同时清理内存中的记录
func (p *Program) AutoDeleteBackend(backendID int) bool {
	delete(p.backEndSet, backendID)
	ok := p.DeleteBackendItem(backendID)
	if ok {
		slog.Info("AutoDeleteBackend succeeded", "backendID", backendID)
	}
	return ok
}
