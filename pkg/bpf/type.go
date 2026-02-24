package bpf

import (
	"fmt"
	"net"
	"strconv"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

// maxPossibilityUnit 定义了概率的最大精度单位 (1024)
const maxPossibilityUnit = 1024

// ServiceKey 对应 eBPF 代码中的 struct svc_key
// 用于在 Service Map 中定位服务或其后端槽位
type ServiceKey struct {
	Address     types.IPv4 `align:"address"`      // 服务虚拟 IPv4 地址
	Port        uint16     `align:"dport"`        // 服务端口
	BackendSlot uint16     `align:"backend_slot"` // 槽位索引: 0=服务元数据, >0=后端槽位
	Proto       uint8      `align:"proto"`        // L4 协议类型
	Scope       uint8      `align:"scope"`        // 查找范围 (Local/Cluster)
	Pad         [2]uint8   `align:"pad"`          // 对齐填充
}

// NewServiceKey 创建一个新的 ServiceKey 实例
func NewServiceKey(ip net.IP, port uint16, proto u8proto.U8proto, scope uint8, slot uint16) *ServiceKey {
	key := ServiceKey{
		Port:        port,
		Proto:       uint8(proto),
		Scope:       scope,
		BackendSlot: slot,
	}
	copy(key.Address[:], ip.To4())
	return &key
}

// ToNetwork 将 ServiceKey 转换为网络字节序
func (k *ServiceKey) ToNetwork() *ServiceKey {
	n := *k
	n.Port = byteorder.HostToNetwork16(n.Port)
	return &n
}

// ToHost 将 ServiceKey 转换为网络字节序
func (k *ServiceKey) ToHost() *ServiceKey {
	h := *k
	h.Port = byteorder.NetworkToHost16(h.Port)
	return &h
}

func (k *ServiceKey) String() string {
	kHost := k // .ToHost()
	addr := net.JoinHostPort(kHost.Address.String(), fmt.Sprintf("%d", kHost.Port))
	if kHost.Scope == loadbalancer.ScopeInternal {
		addr += "/i"
	}
	if k.BackendSlot != 0 {
		addr += " slot: " + strconv.Itoa(int(k.BackendSlot))
	}
	return addr
}

// Action 定义服务调度的策略类型
type Action uint16

const (
	DefaultAction  Action = 0     // 默认 (通常等同于随机)
	RandomAction   Action = 0     // 随机轮询
	WeightedAction Action = 1     // 加权轮询
	RedirectAction Action = 32768 // 服务重定向
)

// ServiceEntry 对应 eBPF 代码中的 struct svc_entry
// 存储服务的元数据或具体的后端槽位配置
type ServiceEntry struct {
	BackendID        BackendId `align:"backend_id"`         // 后端全局 ID
	Count            uint16    `align:"count"`              // 后端总数 (仅在 metadata 中有效)
	Possibility      uint16    `align:"possibility"`        // 权重值 (仅在 backend slot 中有效)
	Action           Action    `align:"action"`             // 调度策略
	WeightRangeUpper uint16    `align:"weight_range_upper"` // 加权区间上限 (用于快速选择)
}

// NewServiceEntry 创建一个新的 ServiceEntry 实例
func NewServiceEntry(backendId BackendId, count uint16, possibility Possibility, action Action) *ServiceEntry {
	value := ServiceEntry{
		BackendID:        backendId,
		Count:            count,
		Possibility:      uint16(possibility.percentage * maxPossibilityUnit),
		Action:           action,
		WeightRangeUpper: uint16(possibility.currentPercentageRangeUpper * maxPossibilityUnit),
	}
	return &value
}

func (s *ServiceEntry) String() string {
	sHost := s.ToHost()
	return fmt.Sprintf("%d %d (%d) [0x%x]", sHost.BackendID, sHost.Count, sHost.Possibility, sHost.Action)
}

// ToNetwork 将 ServiceEntry 转换为网络字节序
func (s *ServiceEntry) ToNetwork() *ServiceEntry {
	n := *s
	// 注意: Payload 数据通常不需要字节序转换,除非明确规定
	return &n
}

// ToHost 将 ServiceEntry 转换为对应的格式
func (s *ServiceEntry) ToHost() *ServiceEntry {
	h := *s
	return &h
}

// BackendId 包装后端 ID 类型
type BackendId struct {
	ID uint32
}

// BackendValue 对应 eBPF 代码中的 struct backend
// 存储后端的物理连接信息
type BackendValue struct {
	Address types.IPv4      `align:"address"` // 后端 Pod IP
	Port    uint16          `align:"port"`    // 后端端口
	Proto   u8proto.U8proto `align:"proto"`   // 协议
	Flags   uint8           `align:"flags"`   // 状态标志
}

// NewBackendValue 创建一个新的 BackendValue 实例
func NewBackendValue(ip net.IP, port uint16, proto u8proto.U8proto, state loadbalancer.BackendState) *BackendValue {
	flags := loadbalancer.NewBackendFlags(state)
	value := BackendValue{
		Port:  port,
		Proto: proto,
		Flags: flags,
	}
	copy(value.Address[:], ip.To4())
	return &value
}

// ToNetwork 将 BackendValue 转换为网络字节序
func (v *BackendValue) ToNetwork() *BackendValue {
	n := *v
	n.Port = byteorder.HostToNetwork16(n.Port)
	return &n
}

// Possibility 辅助结构,用于计算权重
type Possibility struct {
	percentage                  float64
	currentPercentageRangeUpper float64
}
