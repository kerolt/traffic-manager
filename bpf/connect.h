#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

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

// cgroup eBPF 程序返回 1 表示继续执行原始连接, 0表示阻止连接
#define SYS_PROCEED 1

#define LB_SERVICE_MAP_MAX_ENTRIES 65536   // 服务映射最大条目数
#define LB_BACKENDS_MAP_MAX_ENTRIES 65536  // 后端映射最大条目数
#define LB_STATS_MAP_MAX_ENTRIES 6         // 数据面统计项数量

// 外部流量策略查找范围
#define LB_LOOKUP_SCOPE_EXT 0  // ExternalTrafficPolicy=Cluster - 允许任意后端
#define LB_LOOKUP_SCOPE_INT 1  // ExternalTrafficPolicy=Local - 仅本地节点后端

#define CONDITIONAL_PREALLOC 0  // 条件预分配标志

#define MAX_BACKEND_SELECTION 1024  // 后端选择最大迭代次数

#define SVC_ACTION_NORMAL 0            // 普通负载均衡 (随机)
#define SVC_ACTION_WEIGHT 1            // 加权负载均衡
#define SVC_ACTION_MIGRATE 2           // 服务迁移
#define SVC_ACTION_REDIRECT_SVC 32768  // 重定向到其他服务

enum stat_index {
    STAT_CONNECT_ATTEMPTS = 0,
    STAT_SERVICE_MISS = 1,
    STAT_BACKEND_SLOT_MISS = 2,
    STAT_BACKEND_MISS = 3,
    STAT_REWRITE_SUCCESS = 4,
    STAT_UNSUPPORTED_ACTION = 5,
};

// svc_key - 负载均衡服务查找键
// 用于在服务映射表中定位特定的服务配置或其后端槽位
struct svc_key {
    __be32 address;      // 服务虚拟 IPv4 地址 (VIP)
    __be16 dport;        // 目标 L4 端口 (网络字节序), 0 表示通配所有端口
    __u16 backend_slot;  // 槽位索引: 0 代表服务元数据本身; >0 代表具体的后端容器实例槽位
    __u8 proto;          // L4 协议类型 (当前预留,默认为 0)
    __u8 scope;          // 查找范围 (LB_LOOKUP_SCOPE_*): 区分集群内或仅本节点
    __u8 pad[2];         // 字节对齐填充
};

// svc_entry - 负载均衡服务映射条目
// 既可以表示服务元数据 (当 backend_slot=0 时), 也可以表示具体的后端槽位配置
struct svc_entry {
    __u32 backend_id;          // 后端唯一标识符 (指向 backend_map 的键)
    __u16 count;               // 如果是服务元数据,表示该服务下所属的健康后端总数
    __u16 possibility;         // 该槽位的加权概率值 (用于加权轮询)
    __u16 action;              // 针对该服务的调度动作类型 (SVC_ACTION_*)
    __u16 weight_range_upper;  // 加权二分查找的区间上限 (仅供 fast_select 算法使用)
};

// backend - 负载均衡后端端点
// 存储实际处理业务请求的目标容器 (Pod) 的物理寻址信息
struct backend {
    __be32 address;  // 后端容器的 IPv4 地址
    __be16 port;     // 后端业务监听的 L4 端口
    __u8 proto;      // L4 协议类型 (预留)
    __u8 flags;      // 端点状态标志 (如是否存活等)
};

// services_map - 服务与后端槽位的关系映射表
// 存储所有 Service 的元数据以及按索引排列的后端槽位信息
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct svc_key);
    __type(value, struct svc_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, LB_SERVICE_MAP_MAX_ENTRIES);
    __uint(map_flags, CONDITIONAL_PREALLOC);
} services_map SEC(".maps");

// backend_map - 后端端点详细信息映射表
// 键为 backend_id,值为端点的物理地址和端口
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct backend);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, LB_BACKENDS_MAP_MAX_ENTRIES);
    __uint(map_flags, CONDITIONAL_PREALLOC);
} backend_map SEC(".maps");

// stats_map - 数据面路径统计信息
// 用于确认 benchmark 期间流量是否真的命中了 eBPF 重写逻辑
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, LB_STATS_MAP_MAX_ENTRIES);
} stats_map SEC(".maps");

static __always_inline void incr_stat(__u32 key) {
    __u64* value = bpf_map_lookup_elem(&stats_map, &key);
    if (value) {
        __sync_fetch_and_add(value, 1);
    }
}

// 获取数据包目标 IPv4 地址
static __always_inline __be32 ctx_get_dst_ip(const struct bpf_sock_addr* ctx) {
    volatile __u32 dst_ip = ctx->user_ip4;
    return (__be32)dst_ip;
}

// 获取数据包目标端口
static __always_inline __be16 ctx_get_dst_port(const struct bpf_sock_addr* ctx) {
    volatile __u32 dport = ctx->user_port;
    return (__be16)dport;
}

// 修改数据包目标 IPv4 地址
static __always_inline void ctx_set_dst_ip(struct bpf_sock_addr* ctx, __be32 dst_ip) { ctx->user_ip4 = (__u32)dst_ip; }

// 修改数据包目标端口
static __always_inline void ctx_set_dst_port(struct bpf_sock_addr* ctx, __be16 dport) { ctx->user_port = (__u32)dport; }

// 获取数据包来源端口
static __always_inline __be16 ctx_get_src_port(const struct bpf_sock* ctx) {
    volatile __u16 sport = (__u16)ctx->src_port;
    return (__be16)bpf_htons(sport);
}

/**
 * lookup_service - 在 BPF Map 中查询服务元数据
 *
 * 查找策略优先级:
 * 1. 优先尝试本地作用域 (LB_LOOKUP_SCOPE_INT), 匹配 ExternalTrafficPolicy=Local
 * 2. 如果本地未命中, 退而查找集群全域作用域 (LB_LOOKUP_SCOPE_EXT)
 */
static __always_inline struct svc_entry* lookup_service(struct svc_key* key) {
    struct svc_entry* svc;

    // 优先匹配本地端点策略
    key->scope = LB_LOOKUP_SCOPE_INT;
    svc = (struct svc_entry*)bpf_map_lookup_elem(&services_map, key);
    if (svc) return svc;

    // 回退到集群全局策略
    key->scope = LB_LOOKUP_SCOPE_EXT;
    return (struct svc_entry*)bpf_map_lookup_elem(&services_map, key);
}

/**
 * lookup_backend_slot - 查询特定后端槽位的详细条目信息
 */
static __always_inline struct svc_entry* lookup_backend_slot(struct svc_key* key) {
    return (struct svc_entry*)bpf_map_lookup_elem(&services_map, key);
}

/**
 * lookup_backend - 根据全局 ID 查询后端的物理物理信息 (IP:Port)
 */
static __always_inline struct backend* lookup_backend(__u32 backend_id) {
    return (struct backend*)bpf_map_lookup_elem(&backend_map, &backend_id);
}

// ========== 核心后端选择调度算法库 ==========

/**
 * sock_select_random_slot - 基础随机轮询调度
 * @sbc: 候选后端总数
 *
 * 使用内核 PRNG 实现的统计学均匀分布随机选择。
 */
static __always_inline __u64 sock_select_random_slot(int sbc) {
    int slot_index = bpf_get_prandom_u32() % sbc;
    return slot_index + 1;  // 逻辑槽位从 1 开始
}

/**
 * sock_select_weighted_slot - 顺序加权随机调度
 * @sbc: 候选后端总数
 * @key: 对应服务的 Key 模板
 *
 * 算法原理: 顺序遍历槽位,根据各槽位占用的权重份额进行概率滚动。
 * 适用场景: 后端数量较少 (如 < 50) 的场景。
 */
static __always_inline int sock_select_weighted_slot(int sbc, struct svc_key key) {
    int keep_possibility = MAX_BACKEND_SELECTION;
    struct svc_entry* backend_slot;

    for (int i = 1; i <= MAX_BACKEND_SELECTION; i++) {
        if (i > sbc) return -ENETRESET;

        key.backend_slot = i;
        backend_slot = lookup_backend_slot(&key);
        if (!backend_slot) return -ENOENT;

        u32 random_value = bpf_get_prandom_u32();

        // 权重区间判定
        if ((random_value % keep_possibility) < backend_slot->possibility) {
            key.backend_slot = i;
            break;
        }

        keep_possibility -= backend_slot->possibility;
        if (keep_possibility < 0) return -ENOENT;
    }
    return key.backend_slot;
}

/**
 * sock_fast_select_weighted_slot - 快速二分加权调度
 * @sbc: 候选后端总数
 * @key: 对应服务的 Key 模板
 *
 * 算法原理: 利用预先计算好的 weight_range_upper 进行二分定位。
 * 复杂度: O(log N), 性能优异, 支持较大规模集群后端调度。
 */
static __always_inline int sock_fast_select_weighted_slot(int sbc, struct svc_key key) {
    int l = 1, r = sbc;
    struct svc_entry* backend_slot;
    int random_point = bpf_get_prandom_u32() % MAX_BACKEND_SELECTION;

    // 标准二分搜索逻辑
    for (int i = 0; i < 10; i++) {
        if (l == r) return l;

        int mid = (l + r) >> 1;
        key.backend_slot = mid;
        backend_slot = lookup_backend_slot(&key);

        if (!backend_slot) return -ENOENT;

        // 目标定位判定
        if (backend_slot->weight_range_upper == random_point) {
            if (backend_slot->possibility > 0)
                return mid;
            else
                return -ENOENT;
        } else if (backend_slot->weight_range_upper < random_point) {
            l = mid + 1;
        } else {
            r = mid;
        }
    }
    return -ENOENT;
}
