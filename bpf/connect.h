#include "common.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

/**
 * 服务元数据映射表
 * 键为 svc_key,值为 svc_meta 结构体,只保存服务级别元信息。
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct svc_key);
    __type(value, struct svc_meta);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, LB_SERVICE_MAP_MAX_ENTRIES);
    __uint(map_flags, CONDITIONAL_PREALLOC);
} service_meta_map SEC(".maps");

/**
 * 服务后端槽位映射表
 * 键为 svc_slot_key,值为 svc_slot 结构体。
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct svc_slot_key);
    __type(value, struct svc_slot);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, LB_SERVICE_SLOT_MAP_MAX_ENTRIES);
    __uint(map_flags, CONDITIONAL_PREALLOC);
} service_slot_map SEC(".maps");

/**
 * 保存后端槽位与实际后端 ID 的映射关系
 * 用于从服务调度结果的槽位索引解析出具体的后端实例信息
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct backend);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, LB_BACKENDS_MAP_MAX_ENTRIES);
    __uint(map_flags, CONDITIONAL_PREALLOC);
} backend_map SEC(".maps");

/**
 * UDP 会话亲和表
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct udp_affinity_key);
    __type(value, struct udp_affinity_value);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, LB_UDP_AFFINITY_MAP_MAX_ENTRIES);
} udp_affinity_map SEC(".maps");

/**
 * UDP 反向地址恢复表
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct nat_sk_key);
    __type(value, struct nat_sk_value);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, LB_NAT_SK_MAP_MAX_ENTRIES);
} nat_sk_map SEC(".maps");

/**
 * 数据面路径统计信息
 */
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

static __always_inline __be32 ctx_get_dst_ip(const struct bpf_sock_addr* ctx) {
    volatile __u32 dst_ip = ctx->user_ip4;
    return (__be32)dst_ip;
}

static __always_inline __be16 ctx_get_dst_port(const struct bpf_sock_addr* ctx) {
    volatile __u32 dport = ctx->user_port;
    return (__be16)dport;
}

static __always_inline __be32 ctx_get_sk_src_ip(const struct bpf_sock_addr* ctx) {
    if (!ctx->sk) return 0;
    volatile __u32 src_ip = ctx->sk->src_ip4;
    return (__be32)src_ip;
}

static __always_inline __be16 ctx_get_sk_src_port(const struct bpf_sock_addr* ctx) {
    if (!ctx->sk) return 0;
    volatile __u16 sport = (__u16)ctx->sk->src_port;
    return (__be16)bpf_htons(sport);
}

static __always_inline void ctx_set_dst_ip(struct bpf_sock_addr* ctx, __be32 dst_ip) { ctx->user_ip4 = (__u32)dst_ip; }

static __always_inline void ctx_set_dst_port(struct bpf_sock_addr* ctx, __be16 dport) { ctx->user_port = (__u32)dport; }

static __always_inline __be16 ctx_get_src_port(const struct bpf_sock* ctx) {
    volatile __u16 sport = (__u16)ctx->src_port;
    return (__be16)bpf_htons(sport);
}

struct svc_resolution {
    struct svc_key key;
    struct svc_meta meta;
};

static __always_inline struct svc_meta* lookup_service_exact(struct svc_key* key) {
    return (struct svc_meta*)bpf_map_lookup_elem(&service_meta_map, key);
}

/**
 * 在 BPF Map 中查询服务元数据
 *
 * 查找策略优先级:
 * 调用方拿到 resolved->key 后再查槽位，避免依赖 lookup 过程修改入参的副作用。
 */
static __always_inline int resolve_service(struct svc_key key, struct svc_resolution* resolved) {
    struct svc_meta* meta;
    __u8 protos[2] = {key.proto, 0};
    __u8 scopes[2] = {LB_LOOKUP_SCOPE_INT, LB_LOOKUP_SCOPE_EXT};

    // 尝试所有协议类型和查找范围的组合，找到第一个匹配的服务配置
    for (int p = 0; p < 2; p++) {
        if (p == 1 && protos[p] == protos[0]) {
            continue;
        }

        key.proto = protos[p];
        for (int s = 0; s < 2; s++) {
            key.scope = scopes[s];
            meta = lookup_service_exact(&key);
            if (!meta) {
                continue;
            }

            resolved->key = key;
            resolved->meta = *meta;
            return 0;
        }
    }

    return -ENOENT;
}

/**
 * lookup_backend_slot - 查询特定后端槽位的详细条目信息
 */
static __always_inline struct svc_slot* lookup_backend_slot(struct svc_slot_key* key) {
    return (struct svc_slot*)bpf_map_lookup_elem(&service_slot_map, key);
}

/**
 * lookup_backend - 根据全局 ID 查询后端的物理物理信息 (IP:Port)
 */
static __always_inline struct backend* lookup_backend(__u32 backend_id) {
    return (struct backend*)bpf_map_lookup_elem(&backend_map, &backend_id);
}

static __always_inline struct udp_affinity_value* lookup_udp_affinity(struct udp_affinity_key* key) {
    return (struct udp_affinity_value*)bpf_map_lookup_elem(&udp_affinity_map, key);
}

static __always_inline struct nat_sk_value* lookup_nat_sk(struct nat_sk_key* key) {
    return (struct nat_sk_value*)bpf_map_lookup_elem(&nat_sk_map, key);
}

/**
 * sock_select_random_slot - 基础随机轮询调度
 * @sbc: 候选后端总数
 *
 * 使用内核 PRNG 实现的统计学均匀分布随机选择。
 */
static __always_inline __u16 sock_select_random_slot(__u16 sbc) {
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
static __always_inline int sock_select_weighted_slot(__u16 sbc, __u16 total_weight, struct svc_slot_key key) {
    struct svc_slot* backend_slot;
    __u32 random_point;

    if (total_weight == 0) {
        return -ENOENT;
    }

    random_point = bpf_get_prandom_u32() % total_weight;

    for (int i = 1; i <= MAX_BACKEND_SELECTION; i++) {
        if (i > sbc) {
            return -ENETRESET;
        }

        key.backend_slot = i;
        backend_slot = lookup_backend_slot(&key);
        if (!backend_slot) {
            return -ENOENT;
        }

        if (random_point < backend_slot->weight_range_upper) {
            return i;
        }
    }

    return -ENOENT;
}

/**
 * sock_fast_select_weighted_slot - 快速二分加权调度
 * @sbc: 候选后端总数
 * @key: 对应服务的 Key 模板
 *
 * 算法原理: 利用预先计算好的 weight_range_upper 进行二分定位。
 * 复杂度: O(log N), 性能优异, 支持较大规模集群后端调度。
 */
static __always_inline int sock_fast_select_weighted_slot(__u16 sbc, __u16 total_weight, struct svc_slot_key key) {
    int l = 1, r = sbc;
    struct svc_slot* backend_slot;
    int random_point;

    if (total_weight == 0) {
        return -ENOENT;
    }

    random_point = bpf_get_prandom_u32() % total_weight;

    // 标准二分搜索逻辑
    for (int i = 0; i < 10; i++) {
        if (l == r) return l;

        int mid = (l + r) >> 1;
        key.backend_slot = mid;
        backend_slot = lookup_backend_slot(&key);

        if (!backend_slot) return -ENOENT;

        // 目标定位判定
        if (backend_slot->weight_range_upper <= random_point) {
            l = mid + 1;
        } else {
            r = mid;
        }
    }
    return -ENOENT;
}
