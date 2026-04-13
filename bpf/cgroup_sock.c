#include "connect.h"

char _license[] SEC("license") = "GPL";

static __always_inline struct svc_slot_key make_slot_key(struct svc_key svc_key, __u16 slot) {
    struct svc_slot_key slot_key = {
        .address = svc_key.address,
        .dport = svc_key.dport,
        .backend_slot = slot,
        .proto = svc_key.proto,
        .scope = svc_key.scope,
    };

    return slot_key;
}

/**
 * IPv4 连接重定向核心逻辑
 *
 * 核心逻辑流程:
 *  1. 提取 socket 原始尝试连接的目标 IP 和端口。
 *  2. 在服务映射表中查找匹配的负载均衡配置。
 *  3. 根据服务定义的调度策略 (普通/加权) 选择一个后端槽位。
 *  4. 通过后端槽位解析出真实的后端 ID。
 *  5. 获取后端具体的端点信息 (Pod IP:Port)。
 *  6. 修改上下文中的目标地址,将连接流量透明导向选中的后端。
 *
 * 返回值说明:
 *   0          : 成功执行重定向。
 *  -ENXIO      : 服务配置缺失或目前没有可调度的后端。
 *  -ENOENT     : 找不到对应的后端槽位或详细端点信息。
 *  -ENETRESET   : 系统配置冲突或后端数量超出预设限制值。
 *  -1          : 未能识别的服务调度动作类型。
 */
static int sock4_select_backend(struct svc_key key, __u32* selected_backend_id, struct backend* selected_backend) {
    struct svc_resolution svc = {};

    // 先查找 Service 元数据,确认服务存在且有可用后端
    if (resolve_service(key, &svc) < 0 || svc.meta.count == 0) {
        incr_stat(STAT_SERVICE_MISS);
        return -ENXIO;
    }

    struct svc_slot_key slot_key = make_slot_key(svc.key, 0);

    // 通过服务定义的调度策略选择后端槽位
    int selected_slot = 0;
    switch (svc.meta.action) {
        case SVC_ACTION_NORMAL:
            selected_slot = sock_select_random_slot(svc.meta.count);
            break;
        case SVC_ACTION_WEIGHT:
            selected_slot = sock_fast_select_weighted_slot(svc.meta.count, svc.meta.total_weight, slot_key);
            if (selected_slot < 0) return selected_slot;
            break;
        default:
            incr_stat(STAT_UNSUPPORTED_ACTION);
            bpf_printk("Error: unsupported service action type [%d]\n", svc.meta.action);
            return -1;
    }

    // 从 service_slot_map 中查找选定的槽位，获取对应的后端 ID
    slot_key.backend_slot = (__u16)selected_slot;
    struct svc_slot* backend_slot = lookup_backend_slot(&slot_key);
    if (!backend_slot) {
        incr_stat(STAT_BACKEND_SLOT_MISS);
        return -ENOENT;
    }
    __u32 backend_id = backend_slot->backend_id;

    // backend_map 查 Pod IP:Port 等详细信息
    struct backend* backend = lookup_backend(backend_id);
    if (!backend) {
        incr_stat(STAT_BACKEND_MISS);
        return -ENOENT;
    }

    *selected_backend_id = (__u32)backend_id;
    *selected_backend = *backend;

    return 0;
}

static int sock4_forward_entry(struct bpf_sock_addr* ctx, __u8 l4_proto) {
    incr_stat(STAT_CONNECT_ATTEMPTS);

    struct svc_key key = {
        .address = ctx_get_dst_ip(ctx),
        .dport = ctx_get_dst_port(ctx),
        .proto = l4_proto,
    };

    __u32 backend_id = 0;
    struct backend backend = {};
    if (sock4_select_backend(key, &backend_id, &backend) < 0) {
        return -1;
    }

    ctx_set_dst_ip(ctx, backend.address);
    ctx_set_dst_port(ctx, backend.port);
    incr_stat(STAT_REWRITE_SUCCESS);
    return 0;
}

static int sock4_udp_sendmsg_entry(struct bpf_sock_addr* ctx) {
    struct svc_key svc_key = {};
    struct backend backend = {};
    __u32 backend_id = 0;
    __be32 client_ip;
    __be16 client_port;
    struct udp_affinity_key affinity_key = {};
    struct udp_affinity_value affinity_value = {};
    struct udp_affinity_value* existing_affinity;
    struct nat_sk_key nat_key = {};
    struct nat_sk_value nat_value = {};
    __u64 now = bpf_ktime_get_ns();
    struct svc_resolution ignored_svc = {};

    incr_stat(STAT_CONNECT_ATTEMPTS);

    svc_key.address = ctx_get_dst_ip(ctx);
    svc_key.dport = ctx_get_dst_port(ctx);
    svc_key.proto = IPPROTO_UDP;

    if (resolve_service(svc_key, &ignored_svc) < 0) {
        incr_stat(STAT_SERVICE_MISS);
        return 0;
    }

    client_ip = ctx_get_sk_src_ip(ctx);
    client_port = ctx_get_sk_src_port(ctx);

    affinity_key.client_ip = client_ip;
    affinity_key.client_port = client_port;
    affinity_key.svc_ip = svc_key.address;
    affinity_key.svc_port = svc_key.dport;
    affinity_key.proto = IPPROTO_UDP;

    existing_affinity = lookup_udp_affinity(&affinity_key);
    if (existing_affinity) {
        if (now - existing_affinity->updated_at_ns > LB_UDP_STATE_TIMEOUT_NS) {
            bpf_map_delete_elem(&udp_affinity_map, &affinity_key);
            goto select_backend;
        }

        struct backend* backend_ptr = lookup_backend(existing_affinity->backend_id);
        if (backend_ptr) {
            backend_id = existing_affinity->backend_id;
            backend = *backend_ptr;
            existing_affinity->updated_at_ns = now;
            goto rewrite_and_record;
        }

        bpf_map_delete_elem(&udp_affinity_map, &affinity_key);
    }

select_backend:
    if (sock4_select_backend(svc_key, &backend_id, &backend) < 0) {
        return 0;
    }

    affinity_value.backend_id = backend_id;
    affinity_value.updated_at_ns = now;
    bpf_map_update_elem(&udp_affinity_map, &affinity_key, &affinity_value, BPF_ANY);

rewrite_and_record:
    nat_key.backend_ip = backend.address;
    nat_key.backend_port = backend.port;
    nat_key.client_ip = client_ip;
    nat_key.client_port = client_port;
    nat_key.proto = IPPROTO_UDP;

    nat_value.svc_ip = svc_key.address;
    nat_value.svc_port = svc_key.dport;
    nat_value.updated_at_ns = now;
    bpf_map_update_elem(&nat_sk_map, &nat_key, &nat_value, BPF_ANY);

    ctx_set_dst_ip(ctx, backend.address);
    ctx_set_dst_port(ctx, backend.port);
    incr_stat(STAT_REWRITE_SUCCESS);
    return 0;
}

static int sock4_udp_recvmsg_entry(struct bpf_sock_addr* ctx) {
    struct nat_sk_key nat_key = {};
    struct nat_sk_value* nat_value;
    struct svc_key svc_key = {};
    __u64 now = bpf_ktime_get_ns();
    struct svc_resolution ignored_svc = {};

    nat_key.backend_ip = ctx_get_dst_ip(ctx);
    nat_key.backend_port = ctx_get_dst_port(ctx);
    nat_key.client_ip = ctx_get_sk_src_ip(ctx);
    nat_key.client_port = ctx_get_sk_src_port(ctx);
    nat_key.proto = IPPROTO_UDP;

    nat_value = lookup_nat_sk(&nat_key);
    if (!nat_value) {
        return 0;
    }

    if (now - nat_value->updated_at_ns > LB_UDP_STATE_TIMEOUT_NS) {
        bpf_map_delete_elem(&nat_sk_map, &nat_key);
        return 0;
    }

    svc_key.address = nat_value->svc_ip;
    svc_key.dport = nat_value->svc_port;
    svc_key.proto = IPPROTO_UDP;

    if (resolve_service(svc_key, &ignored_svc) < 0) {
        bpf_map_delete_elem(&nat_sk_map, &nat_key);
        return 0;
    }

    nat_value->updated_at_ns = now;

    ctx_set_dst_ip(ctx, nat_value->svc_ip);
    ctx_set_dst_port(ctx, nat_value->svc_port);
    return 0;
}

/**
 * sock4_connect - IPv4 建立连接时的 eBPF 挂钩处理函数
 * 触发时机: socket 层级调用 connect() 尝试握手前
 * 挂载位置: cgroup/connect4
 *
 * 此入口负责调用重定向逻辑。无论重定向是否成功触发,都会继续内核连接流程,
 * 但重定向成功后,内核连接的目标三元组已被此程序实时篡改。
 */
SEC("cgroup/connect4")
int sock4_connect(struct bpf_sock_addr* ctx) {
    if (ctx->protocol != IPPROTO_TCP) {
        return SYS_PROCEED;
    }

    // 启动连接映射流程
    sock4_forward_entry(ctx, (__u8)ctx->protocol);

    // 始终返回 SYS_PROCEED (1),指示内核继续发起连接动作
    // 如果重定向成功,内核将直接向后端 IP 发起握手
    return SYS_PROCEED;
}

/**
 * sock4_sendmsg - IPv4 UDP 发送数据时的 eBPF 挂钩处理函数
 * 触发时机: socket 层级 sendmsg/sendto
 * 挂载位置: cgroup/sendmsg4
 */
SEC("cgroup/sendmsg4")
int sock4_sendmsg(struct bpf_sock_addr* ctx) {
    sock4_udp_sendmsg_entry(ctx);
    return SYS_PROCEED;
}

/**
 * sock4_recvmsg - IPv4 UDP 接收数据时的 eBPF 挂钩处理函数
 * 触发时机: socket 层级 recvmsg/recvfrom
 * 挂载位置: cgroup/recvmsg4
 */
SEC("cgroup/recvmsg4")
int sock4_recvmsg(struct bpf_sock_addr* ctx) {
    sock4_udp_recvmsg_entry(ctx);

    // 始终返回 SYS_PROCEED (1),指示内核继续发起连接动作
    // 如果重定向成功,内核将直接向后端 IP 发起握手
    return SYS_PROCEED;
}
