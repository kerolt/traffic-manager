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
	flag.Parse()

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

	// 监听 SIGINT/SIGTERM 信号，收到后优雅退出，defer 会自动清理 eBPF 资源
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
