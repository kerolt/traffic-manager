#ifndef COMMON_H_
#define COMMON_H_

#include "vmlinux.h"

#ifndef EPERM
#define EPERM 1  // 操作权限不足
#endif
#ifndef ENOENT
#define ENOENT 2  // 文件/条目不存在
#endif
#ifndef ENXIO
#define ENXIO 6  // 设备或地址不存在
#endif
#ifndef ENOMEM
#define ENOMEM 12  // 内存不足
#endif
#ifndef EFAULT
#define EFAULT 14  // 内存访问错误
#endif
#ifndef EINVAL
#define EINVAL 22  // 无效参数
#endif
#ifndef ENOTSUP
#define ENOTSUP 95  // 操作不支持
#endif
#ifndef EADDRINUSE
#define EADDRINUSE 98  // 地址已被占用
#endif
#ifndef ENOTSUPP
#define ENOTSUPP 524  // 操作不支持
#endif
#ifndef ENETRESET
#define ENETRESET 3434  // 连接被重置
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

// cgroup eBPF 程序返回 1 表示继续执行原始连接, 0表示阻止连接
#define SYS_PROCEED 1

#define LB_SERVICE_MAP_MAX_ENTRIES 65536       // 服务元数据映射最大条目数
#define LB_SERVICE_SLOT_MAP_MAX_ENTRIES 65536  // 服务后端槽位映射最大条目数
#define LB_BACKENDS_MAP_MAX_ENTRIES 65536      // 后端映射最大条目数
#define LB_STATS_MAP_MAX_ENTRIES 6             // 数据面统计项数量
#define LB_UDP_AFFINITY_MAP_MAX_ENTRIES 262144
#define LB_NAT_SK_MAP_MAX_ENTRIES 262144
#define LB_UDP_STATE_TIMEOUT_NS 60000000000ULL

// 外部流量策略查找范围
#define LB_LOOKUP_SCOPE_EXT 0  // ExternalTrafficPolicy=Cluster - 允许任意后端
#define LB_LOOKUP_SCOPE_INT 1  // ExternalTrafficPolicy=Local - 仅本地节点后端

#define CONDITIONAL_PREALLOC 0  // 条件预分配标志

#define MAX_BACKEND_SELECTION 1024  // 后端选择最大迭代次数

#define SVC_ACTION_NORMAL 0  // 普通负载均衡 (随机)
#define SVC_ACTION_WEIGHT 1  // 加权负载均衡

enum stat_index {
    STAT_CONNECT_ATTEMPTS = 0,
    STAT_SERVICE_MISS = 1,
    STAT_BACKEND_SLOT_MISS = 2,
    STAT_BACKEND_MISS = 3,
    STAT_REWRITE_SUCCESS = 4,
    STAT_UNSUPPORTED_ACTION = 5,
};

/**
 * service meta key
 * 用于在服务元数据映射表中定位特定的服务配置
 * - VIP: address + dport
 * - proto: 协议类型
 * - scope: 查找范围 (集群内或仅本节点)
 */
struct svc_key {
    __be32 address;
    __be16 dport;
    __u8 proto;
    __u8 scope;
};

/**
 * service slot key
 * 用于在服务后端槽位映射表中定位特定的后端槽位配置
 */
struct svc_slot_key {
    __be32 address;
    __be16 dport;
    __u16 backend_slot;
    __u8 proto;
    __u8 scope;
    __u8 pad[2];
};

/**
 * 负载均衡服务元数据
 * - count: 服务下的健康后端总数
 * - action: 服务的调度动作类型 (如随机/加权)
 * - total_weight: 加权调度时的总权重
 */
struct svc_meta {
    __u16 count;
    __u16 action;
    __u16 total_weight;
    __u16 pad;
};

/**
 * 负载均衡服务后端槽位配置
 * - backend_id: 仅当 backend_slot>0 时有效, 指向后端映射表的键
 * - possibility: 加权调度时该槽位被选中的概率值 (相对值,非百分比)
 * - weight_range_upper: 加权二分调度时该槽位的权重区间上限 (仅供 fast_select 算法使用)
 */
struct svc_slot {
    __u32 backend_id;
    __u16 possibility;
    __u16 weight_range_upper;
};

/**
 * 负载均衡后端端点，存储实际处理业务请求的目标容器 (Pod) 的物理寻址信息
 * - address: 后端容器的 IPv4 地址
 * - port: 后端业务监听的 L4 端口
 * - proto: 协议类型
 * - flags: 端点状态标志 (如是否存活等)
 */
struct backend {
    __be32 address;
    __be16 port;
    __u8 proto;
    __u8 flags;
};

/**
 * UDP 亲和会话查找键
 * 使用客户端 socket 四元组 + Service 四元组，保证同会话稳定命中同一后端
 */
struct udp_affinity_key {
    __be32 client_ip;
    __be16 client_port;
    __be16 pad0;
    __be32 svc_ip;
    __be16 svc_port;
    __u8 proto;
    __u8 pad1;
};

struct udp_affinity_value {
    __u32 backend_id;
    __u64 updated_at_ns;
};

/**
 * UDP 反向地址恢复查找键
 * 使用后端源地址 + 客户端 socket 四元组，定位对应的 Service VIP:VPORT
 */
struct nat_sk_key {
    __be32 backend_ip;
    __be16 backend_port;
    __be16 pad0;
    __be32 client_ip;
    __be16 client_port;
    __u8 proto;
    __u8 pad1;
};

struct nat_sk_value {
    __be32 svc_ip;
    __be16 svc_port;
    __u16 pad;
    __u64 updated_at_ns;
};

#endif /* COMMON_H_ */
