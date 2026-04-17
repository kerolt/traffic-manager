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
// 用于在 Service Meta Map 中定位服务元数据
type ServiceKey struct {
	Address types.IPv4 `align:"address"` // 服务虚拟 IPv4 地址
	Port    uint16     `align:"dport"`   // 服务端口
	Proto   uint8      `align:"proto"`   // L4 协议类型
	Scope   uint8      `align:"scope"`   // 查找范围 (Local/Cluster)
}

// NewServiceKey 创建一个新的 ServiceKey 实例
func NewServiceKey(ip net.IP, port uint16, proto u8proto.U8proto, scope uint8) *ServiceKey {
	key := ServiceKey{
		Port:  port,
		Proto: uint8(proto),
		Scope: scope,
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
	return addr
}

// ServiceSlotKey 对应 eBPF 代码中的 struct svc_slot_key
// 用于在 Service Slot Map 中定位服务后端槽位。
type ServiceSlotKey struct {
	Address     types.IPv4 `align:"address"`
	Port        uint16     `align:"dport"`
	BackendSlot uint16     `align:"backend_slot"`
	Proto       uint8      `align:"proto"`
	Scope       uint8      `align:"scope"`
	pad         [2]uint8   `align:"pad"`
}

func NewServiceSlotKey(ip net.IP, port uint16, proto u8proto.U8proto, scope uint8, slot uint16) *ServiceSlotKey {
	key := ServiceSlotKey{
		Port:        port,
		Proto:       uint8(proto),
		Scope:       scope,
		BackendSlot: slot,
	}
	copy(key.Address[:], ip.To4())
	return &key
}

func (k *ServiceSlotKey) ToNetwork() *ServiceSlotKey {
	n := *k
	n.Port = byteorder.HostToNetwork16(n.Port)
	return &n
}

func (k *ServiceSlotKey) String() string {
	addr := net.JoinHostPort(k.Address.String(), fmt.Sprintf("%d", k.Port))
	if k.Scope == loadbalancer.ScopeInternal {
		addr += "/i"
	}
	addr += " slot: " + strconv.Itoa(int(k.BackendSlot))
	return addr
}

// ServiceMeta 对应 eBPF 代码中的 struct svc_meta，存储服务元数据。
type ServiceMeta struct {
	Count       uint16 `align:"count"`
	Action      Action `align:"action"`
	TotalWeight uint16 `align:"total_weight"`
	Pad         uint16 `align:"pad"`
}

func NewServiceMeta(count uint16, action Action, totalWeight uint16) *ServiceMeta {
	return &ServiceMeta{
		Count:       count,
		Action:      action,
		TotalWeight: totalWeight,
	}
}

func (s *ServiceMeta) String() string {
	sHost := s.ToHost()
	return fmt.Sprintf("%d (%d) [0x%x]", sHost.Count, sHost.TotalWeight, sHost.Action)
}

func (s *ServiceMeta) ToNetwork() *ServiceMeta {
	n := *s
	return &n
}

func (s *ServiceMeta) ToHost() *ServiceMeta {
	h := *s
	return &h
}

type ServiceEntry = ServiceMeta

// ServiceSlot 对应 eBPF 代码中的 struct svc_slot
// 存储服务后端槽位配置。
type ServiceSlot struct {
	BackendID        BackendId `align:"backend_id"`
	Possibility      uint16    `align:"possibility"`
	WeightRangeUpper uint16    `align:"weight_range_upper"`
}

func NewServiceSlot(backendId BackendId, possibility Possibility) *ServiceSlot {
	return &ServiceSlot{
		BackendID:        backendId,
		Possibility:      uint16(possibility.percentage * maxPossibilityUnit),
		WeightRangeUpper: uint16(possibility.currentPercentageRangeUpper * maxPossibilityUnit),
	}
}

func (s *ServiceSlot) String() string {
	return fmt.Sprintf("%d (%d/%d)", s.BackendID.ID, s.Possibility, s.WeightRangeUpper)
}

func (s *ServiceSlot) ToNetwork() *ServiceSlot {
	n := *s
	return &n
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
