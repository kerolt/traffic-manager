// traffic-manager 是一个基于 eBPF 的 Kubernetes Service 流量管理工具。
// 它通过 Kubernetes API 获取指定 Service 及其后端 Pod 信息，
// 然后将服务和后端信息写入 eBPF Maps，
// 并挂载 eBPF 程序到 cgroup 的 connect4 钉子以实现透明化负载均衡。
package main

import (
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/kerolt/traffic-manager/pkg/bpf"
	"github.com/kerolt/traffic-manager/pkg/client"
	"github.com/kerolt/traffic-manager/pkg/controller"
)

func main() {
	// 解析命令行参数
	kubeconfig := flag.String("kubeconfig", "", "path of config")
	metricsAddr := flag.String("metrics-addr", "", "prometheus address for metrics (e.g. http://prometheus:9090)")
	checkServiceIP := flag.String("check-service-ip", "", "service IP to check in pinned BPF maps")
	checkServicePort := flag.String("check-service-port", "", "service port to check in pinned BPF maps")
	dumpStats := flag.Bool("dump-stats", false, "print pinned BPF stats and exit")
	flag.Parse()

	if *dumpStats {
		stats, err := bpf.ReadPinnedStats()
		if err != nil {
			// 使用 slog 的结构化错误处理，避免冗余的字符串拼接
			slog.Error("failed to read pinned stats", "error", err)
			os.Exit(1)
		}

		// 将 stats 聚合在一个 Group 中，输出会更具组织性
		slog.Info("BPF metrics dump",
			slog.Group("stats",
				slog.Uint64("connect_attempts", stats.ConnectAttempts),
				slog.Uint64("service_misses", stats.ServiceMisses),
				slog.Uint64("backend_slot_misses", stats.BackendSlotMisses),
				slog.Uint64("backend_misses", stats.BackendMisses),
				slog.Uint64("rewrite_successes", stats.RewriteSuccesses),
				slog.Uint64("unsupported_actions", stats.UnsupportedAction),
			),
		)
		return
	}

	// check-service-ip 和 check-service-port 必须同时提供，否则会导致不一致的检查逻辑
	if (*checkServiceIP == "") != (*checkServicePort == "") {
		slog.Error("check-service-ip and check-service-port must be used together")
		os.Exit(2)
	}

	if *checkServiceIP != "" {
		exists, service, err := bpf.LookupPinnedService(*checkServiceIP, *checkServicePort)
		if err != nil {
			slog.Error("Failed to check pinned service", "error", err)
			os.Exit(1)
		}
		if !exists {
			os.Exit(1)
		}

		slog.Info("Pinned service found", "serviceIP", *checkServiceIP, "servicePort", *checkServicePort, "backends", service.Count, "action", service.Action)
		return
	}

	if *kubeconfig == "" {
		*kubeconfig = client.GetDefaultKubeConfigFile()
	}

	clientSet, err := client.BuildClientSet(*kubeconfig)
	if err != nil {
		slog.Error("Failed to build client set", "error", err)
		return
	}

	// 加载 eBPF 程序和 Maps
	program, err := bpf.LoadProgram()
	if err != nil {
		slog.Error("Loading program failed", "error", err)
		return
	}
	defer program.Close()

	// 将 eBPF 程序挂载到 cgroup 的 connect4 拦截连接
	err = program.Attach()
	if err != nil {
		slog.Error("Attaching failed", "error", err)
		return
	}

	// 启动 Controller
	ctrl := controller.NewController(clientSet, &program, *metricsAddr)
	stopCh := make(chan struct{})

	// 监听 SIGINT/SIGTERM 信号，收到后优雅退出
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-quit
		slog.Info("Shutting down...")
		close(stopCh)
	}()

	slog.Info("Running, press Ctrl+C to stop")
	if err := ctrl.Run(stopCh); err != nil {
		slog.Error("Controller failed", "error", err)
	}
}
