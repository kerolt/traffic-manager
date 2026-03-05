// Package metrics 提供集群节点负载指标的采集与查询能力。
// 通过 Prometheus + node-exporter 获取各节点的 CPU 负载数据，
// 并将其抽象为统一接口供上层负载均衡决策使用。
package metrics

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/api"
	v1 "github.com/prometheus/client_golang/api/prometheus/v1"
	"github.com/prometheus/common/model"
)

// Metric 是所有指标值的通用标记接口。
// 各具体指标类型通过实现此接口以便在 ClusterMetric.Query 中统一返回。
type Metric interface {
}

// NodeMetric 表示单个节点的指标抽象。
// Update 从集群指标中刷新当前节点的数据；
// AvailableRate 返回该节点的可用率（0.0 ~ 1.0），供负载均衡权重计算使用。
type NodeMetric interface {
	Update(cm ClusterMetric) error
	AvailableRate() float64
}

// ClusterMetric 表示整个集群的指标抽象。
// Update 从外部数据源（如 Prometheus）拉取最新数据；
// AvailableRate 返回集群整体可用率；
// Query 根据节点名称查询该节点的具体 Metric 值。
type ClusterMetric interface {
	Update() error
	AvailableRate() float64
	Query(name string) Metric
}

// NodeExporterMetric 存储单次采集到的节点负载数据（当前仅使用 1 分钟平均负载）。
type NodeExporterMetric struct {
	Load1 float64
}

// NodeExporterNodeMetric 实现 NodeMetric 接口，代表单个节点通过 node-exporter 采集的指标。
// name 为节点标识（通常为 IP:port 去掉端口后的 IP 地址）；
// load1 为最近 1 分钟的 CPU 平均负载；
// mu 用于保护并发读写。
type NodeExporterNodeMetric struct {
	name  string
	load1 float64
	mu    sync.Mutex
}

// Update 从 ClusterMetric 中拉取当前节点最新的 load1 值并更新到本地缓存。
func (nm *NodeExporterNodeMetric) Update(metric ClusterMetric) error {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	nm.load1 = metric.Query(nm.name).(NodeExporterNodeMetric).load1
	return nil
}

// AvailableRate 根据 load1 计算节点可用率。
// 当 load1 >= 10 时认为节点过载，返回 0；否则返回 (10 - load1) / 10。
func (nm *NodeExporterNodeMetric) AvailableRate() float64 {
	if nm.load1 > 10 {
		return 0
	} else {
		return (10 - nm.load1) / 10
	}
}

// NodeExporterClusterMetrics 实现 ClusterMetric 接口，
// 通过 Prometheus HTTP API 查询集群内各节点的 node-exporter 指标。
// Address 为 Prometheus 服务地址；
// load1 为所有节点 load1 的累计值；
// data 为节点名 -> load1 的映射缓存；
// mu 用于保护 data 的并发读写。
type NodeExporterClusterMetrics struct {
	Address string
	load1   float64
	data    map[string]float64
	mu      sync.Mutex
}

// Update 从 Prometheus 拉取最新的 node-exporter load1 数据，
// 并以加锁方式更新内部缓存 data。
func (cm *NodeExporterClusterMetrics) Update() error {
	log.Printf("[INFO] Fetching Node Exporter data...")
	load1Data, err := cm.GetLoad1Data(cm.Address)
	if err != nil {
		return fmt.Errorf("error fetching load1 data: %v", err)
	}
	cm.mu.Lock()
	cm.data = load1Data
	cm.mu.Unlock()
	return nil
}

// AvailableRate 返回集群整体可用率，当前固定返回 1（暂未实现集群级别的负载评估）。
func (cm *NodeExporterClusterMetrics) AvailableRate() float64 {
	return 1
}

// Query 根据节点名称从缓存中获取对应的 NodeExporterNodeMetric。
// 若节点不存在，load1 默认为 0。
func (cm *NodeExporterClusterMetrics) Query(name string) Metric {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	return NodeExporterNodeMetric{name: name, load1: cm.data[name], mu: sync.Mutex{}}
}

// GetLoad1Data 通过 Prometheus HTTP API 查询所有 node-exporter 节点
// 最近 1 分钟的平均 CPU 负载（node_load1），返回节点 IP -> load1 的映射。
// 同时将所有节点 load1 的累计值写入 cm.load1。
func (cm *NodeExporterClusterMetrics) GetLoad1Data(prometheusAddress string) (map[string]float64, error) {
	client, err := api.NewClient(api.Config{
		Address: prometheusAddress,
	})
	if err != nil {
		return nil, err
	}

	query := `avg_over_time(node_load1{job="node-exporter"}[1m])`

	promAPI := v1.NewAPI(client)
	result, _, err := promAPI.QueryRange(
		context.TODO(),
		query,
		v1.Range{Start: time.Now().Add(-1 * time.Minute), End: time.Now(), Step: time.Minute},
	)
	if err != nil {
		return nil, err
	}

	load1Data := make(map[string]float64)
	matrix, ok := result.(model.Matrix)
	if !ok {
		return nil, fmt.Errorf("unexpected result type")
	}
	totalLoad1 := 0.0
	for _, sample := range matrix {
		node := strings.Replace(string(sample.Metric["instance"]), ":9100", "", 1)
		load1 := float64(sample.Values[0].Value)
		totalLoad1 += load1
		load1Data[node] = load1
	}

	cm.load1 = totalLoad1
	return load1Data, nil
}

// GetPromHost 通过 kubectl 命令查询 Kubernetes control-plane 节点的内部 IP，
// 并拼接为 Prometheus 的访问地址（默认端口 9090）。
// 假设 Prometheus 部署在 control-plane 节点上。
func GetPromHost() (string, error) {
	// command := `kubectl get nodes -o=jsonpath='{.items[?(@.metadata.labels.node-role\.kubernetes\.io/control-plane=="")].status.addresses[?(@.type=="InternalIP")].address}'`
	cmd := exec.Command("kubectl", "get", "nodes", "-o=jsonpath={.items[?(@.metadata.labels.node-role\\.kubernetes\\.io/control-plane==\"\")].status.addresses[?(@.type==\"InternalIP\")].address}")

	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("error executing kubectl command: %s", err)
	}

	address := strings.Trim(string(output), " \n")
	promHost := fmt.Sprintf("http://%s:9090", address)
	fmt.Println("Prometheus URL:", promHost)
	return promHost, nil
}
