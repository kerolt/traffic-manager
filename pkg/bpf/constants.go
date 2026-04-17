package bpf

const MapsPinPath = "/sys/fs/bpf/sock_ops_map"

const (
	ServiceMapPinPath     = MapsPinPath + "/service_meta_map"
	ServiceSlotMapPinPath = MapsPinPath + "/service_slot_map"
	BackendMapPinPath     = MapsPinPath + "/backend_map"
	StatsMapPinPath       = MapsPinPath + "/stats_map"
	UdpAffinityMapPinPath = MapsPinPath + "/udp_affinity_map"
	NatSkMapPinPath       = MapsPinPath + "/nat_sk_map"
)

const (
	statConnectAttempts uint32 = iota
	statServiceMiss
	statBackendSlotMiss
	statBackendMiss
	statRewriteSuccess
	statUnsupportedAction
)

// Action 定义服务调度的策略类型
type Action uint16

const (
	DefaultAction  Action = 0 // 默认 (通常等同于随机)
	RandomAction   Action = 0 // 随机轮询
	WeightedAction Action = 1 // 加权轮询
)

type TrafficStats struct {
	ConnectAttempts   uint64
	ServiceMisses     uint64
	BackendSlotMisses uint64
	BackendMisses     uint64
	RewriteSuccesses  uint64
	UnsupportedAction uint64
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
