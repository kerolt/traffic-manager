# Traffic Manager

**Traffic Manager** 是一个基于 **eBPF** 的轻量级 Kubernetes Service L4 透明流量管理和负载均衡工具。

它工作在 Linux Socket 层，通过将 eBPF 程序挂载到 `cgroup` 的 `connect4` 钩子上，在应用程序级别的 `connect()` 系统调用时动态且透明地拦截并重写目标 IP 地址，从而将流量从服务虚拟 IP（VIP）直接调度并负载均衡到真实的后端 Pod 上。

**无需修改应用程序代码，也不依赖复杂的 iptables/kube-proxy/IPVS 规则链。**

## 核心特性

- **基于 eBPF 的高性能透明拦截**：在 `connect()` 系统调用最早时机完成 VIP → Pod IP 重写，完全绕过 iptables/netfilter 规则链，降低网络栈路径长度。
- **Informer + Workqueue 控制器模式**：遵循 Kubernetes 标准控制器最佳实践，通过 EndpointSlice Informer 监听 Service 及 Pod Endpoints 变化，实时热更新 eBPF Maps。
- **多种负载均衡策略**：支持随机（Normal）、加权（Weighted）及服务级联重定向（Redirect）三种调度模式，权重可根据 Prometheus 节点指标动态计算。
- **可观测性集成**：通过 `--metrics-addr` 启用 Prometheus 指标暴露，提供连接尝试数、BPF Map 命中率、成功转发次数等数据面运行状态。
- **优雅的生命周期管理**：支持 SIGINT/SIGTERM 信号驱动的优雅退出，退出时自动卸载 cgroup 钩子、unpin 并关闭所有 BPF Maps。

## 性能基准

在 Minikube 单节点环境下，使用 `siege` 对 Deployment Service（25 个后端 Pod）进行 200 并发 15 秒短连接压测的基准对比结果：

| 场景 | 方案 | Trans/sec (QPS) | 相对变化 |
|---|---|---|---|
| 正常场景 | kube-proxy (iptables) | ~8,818 | baseline |
| 正常场景 | Traffic Manager (eBPF) | ~10,535 | **+19.47%** |
| 500 个干扰 Service | kube-proxy (iptables) | ~8,568 | baseline |
| 500 个干扰 Service | Traffic Manager (eBPF) | ~10,945 | **+27.74%** |

> iptables 规则匹配复杂度为 O(n)（随 Service 数量线性增长），而 eBPF `BPF_MAP_TYPE_HASH` 查表复杂度为 O(1)。从数据可以看出，随着集群 Service 数量增加，eBPF 方案的相对优势从 **+19.47%** 进一步扩大到 **+27.74%**，在大规模集群场景下优势更加显著。

## 快速开始

### 前置环境要求

- **操作系统**：Linux，内核版本 ≥ 5.7（需支持 `cgroup/connect4` eBPF 程序类型）
- **Cgroup**：必须挂载并启用 `cgroup v2`
- **BPF 文件系统**：`/sys/fs/bpf` 需已挂载（minikube 等环境需手动挂载：`sudo mount -t bpf bpf /sys/fs/bpf`）
- **权限**：需要 `root` 权限或具备 `CAP_BPF` / `CAP_NET_ADMIN` 能力
- **编译工具链**：`clang`、`llvm`、`libbpf-dev` / `bpftool`
- **Go 环境**：Go ≥ 1.23
- **集群访问**：已配置 kubeconfig 并可连接 Kubernetes API Server

### 构建

Traffic Manager 使用 `bpf2go` 将 eBPF C 代码编译嵌入 Go 二进制。

```bash
# 1. 生成 eBPF Go 绑定（仅在修改 bpf/*.c 后需要重新执行）
cd pkg/bpf && go generate && cd ../..

# 2. 编译主程序
go build -o bin/traffic-manager main.go
```

### 运行

```bash
# 基本启动（默认读取 ~/.kube/config）
sudo ./bin/traffic-manager

# 指定 kubeconfig 并启用 Prometheus Metrics
sudo ./bin/traffic-manager -kubeconfig=/path/to/kube.conf -metrics-addr=:9090
```

按 `Ctrl+C` 或发送 `SIGTERM` 信号即可优雅退出，程序会自动卸载 cgroup 钩子并清理所有 BPF Maps。

### 快速验证（Minikube）

```bash
# 一键验证 eBPF 加速效果（自动构建、部署、压测、对比）
chmod +x scripts/benchmark-minikube.sh
./scripts/benchmark-minikube.sh

# 验证大规模 Service 场景下的性能优势（Case F：1000 个干扰 Service）
DUMMY_SVC_COUNT=1000 ./scripts/benchmark-minikube.sh --rule-bloat
```
