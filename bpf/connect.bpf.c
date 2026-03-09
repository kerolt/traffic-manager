#include "connect.h"

char _license[] SEC("license") = "GPL";

// ========== 示例常量定义 (生产环境通常从配置映射读取) ==========
/**
 * 示例配置常量 (实际运行建议从配置映射或 BPF 全局变量读取)
 * service_ip: 10.7.111.132 (网络字节序: 0x846F070A)
 * pod_ip:    127.0.0.1    (网络字节序: 0x0100007F)
 * service_port: 80        (网络字节序: 0x0050 / 0x5000)
 * pod_port:   8080        (网络字节序: 0x1F90 / 0x901f)
 */
const __be32 service_ip = 0x846F070A;  // 服务虚拟 IP (VIP)
const __be32 pod_ip = 0x0100007F;      // 目标 Pod IP
const __be16 service_port = 0x5000;    // 服务端口
const __be16 pod_port = 0x901f;        // 目标业务端口

/**
 * sock4_forward_entry - IPv4 连接重定向核心逻辑
 * @ctx: eBPF 上下文,包含 socket 地址信息
 *
 * 核心逻辑流程:
 * 1. 提取 socket 原始尝试连接的目标 IP 和端口。
 * 2. 在服务映射表中查找匹配的负载均衡配置。
 * 3. 根据服务定义的调度策略 (普通/加权/重定向) 选择一个后端槽位。
 * 4. 通过后端槽位解析出真实的后端 ID。
 * 5. 获取后端具体的端点信息 (Pod IP:Port)。
 * 6. 修改上下文中的目标地址,将连接流量透明导向选中的后端。
 *
 * 返回值说明:
 *   0          : 成功执行重定向。
 *  -ENXIO      : 服务配置缺失或目前没有可调度的后端。
 *  -ENOENT     : 找不到对应的后端槽位或详细端点信息。
 *  -ENETRESET   : 系统配置冲突或后端数量超出预设限制值。
 *  -1          : 未能识别的服务调度动作类型。
 */
static int sock4_forward_entry(struct bpf_sock_addr* ctx) {
    incr_stat(STAT_CONNECT_ATTEMPTS);

    // 定义查找键结构
    struct svc_key key = {}, orig_key;
    struct svc_entry* svc;
    struct svc_entry* backend_slot;
    int backend_id = -1;
    struct backend* backend;

    // 第一步: 采集原始尝试接入的目标信息
    __be32 ori_dst_ip = ctx_get_dst_ip(ctx);
    __be16 ori_dst_port = ctx_get_dst_port(ctx);

    // 构造查找服务的 Key: backend_slot 为 0 代表查找服务元数据
    key.address = ori_dst_ip;
    key.dport = ori_dst_port;
    key.backend_slot = 0;
    orig_key = key;

    // 第二步: 验证服务是否存在及其健康状态
    svc = lookup_service(&key);
    if (!svc || svc->count == 0) {
        incr_stat(STAT_SERVICE_MISS);
        return -ENXIO;
    }

    // 第三步: 按照算法决策选出的后端槽位索引
    switch (svc->action) {
        case SVC_ACTION_NORMAL:
            // 轮询随机选择算法
            key.backend_slot = sock_select_random_slot(svc->count);
            break;
        case SVC_ACTION_WEIGHT:
            // 比例加权调度算法
            key.backend_slot = sock_select_weighted_slot(svc->count, key);
            if (key.backend_slot < 0) return key.backend_slot;
            break;
        case SVC_ACTION_REDIRECT_SVC:
            // 级联服务重定向: 支持将一个 Service 指向另一个 Service
            // 此处多预留一个槽位用于判断是否命中重定向目标
            key.backend_slot = sock_fast_select_weighted_slot(svc->count + 1, key);

            if (key.backend_slot > svc->count) {
                // 命中重定向逻辑
                backend_slot = lookup_backend_slot(&key);
                if (!backend_slot) {
                    incr_stat(STAT_BACKEND_SLOT_MISS);
                    return -ENOENT;
                }
                backend_id = backend_slot->backend_id;

                // 递归查找目标服务的端点信息
                backend = lookup_backend(backend_id);
                if (!backend) {
                    incr_stat(STAT_BACKEND_MISS);
                    return -ENOENT;
                }

                // 以重定向后的地址作为新起点重新进行后端选择
                key = orig_key;
                key.address = backend->address;
                key.dport = backend->port;

                key.backend_slot = sock_fast_select_weighted_slot(svc->count, key);
                if (key.backend_slot < 0) return key.backend_slot;
            }
            break;

        default:
            incr_stat(STAT_UNSUPPORTED_ACTION);
            bpf_printk("Error: unsupported service action type [%d]\n", svc->action);
            return -1;
    }

    // 第四步: 确立后端槽位元数据
    backend_slot = lookup_backend_slot(&key);
    if (!backend_slot) {
        incr_stat(STAT_BACKEND_SLOT_MISS);
        return -ENOENT;
    }
    backend_id = backend_slot->backend_id;

    // 第五步: 提取后端的物理连接元组 (IP & Port)
    backend = lookup_backend(backend_id);
    if (!backend) {
        incr_stat(STAT_BACKEND_MISS);
        return -ENOENT;
    }

    // 第六步: 将连接的目标变更为后端 Pod 地址,从而实现负载均衡的分发逻辑
    ctx_set_dst_ip(ctx, backend->address);
    ctx_set_dst_port(ctx, backend->port);

    incr_stat(STAT_REWRITE_SUCCESS);

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
    // 启动连接映射流程
    sock4_forward_entry(ctx);

    // 始终返回 SYS_PROCEED (1),指示内核继续发起连接动作
    // 如果重定向成功,内核将直接向后端 IP 发起握手
    return SYS_PROCEED;
}
