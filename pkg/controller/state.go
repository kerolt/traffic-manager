package controller

import (
	"log/slog"
	"math"
	"strconv"

	"github.com/kerolt/traffic-manager/pkg/bpf"
	"github.com/kerolt/traffic-manager/pkg/metrics"
	discovery1 "k8s.io/api/discovery/v1"
)

// buildPodStates 根据 EndpointSlice 列表构建后端 Pod 的状态信息，包括 IP、端口、权重和健康状态。
func (c *Controller) buildPodStates(endpointSlices []*discovery1.EndpointSlice, svcPort string) []podState {
	var pods []podState

	for _, endpointSlice := range endpointSlices {
		portStr := svcPort
		if len(endpointSlice.Ports) > 0 && endpointSlice.Ports[0].Port != nil {
			portStr = strconv.Itoa(int(*endpointSlice.Ports[0].Port))
		}

		for _, endpoint := range endpointSlice.Endpoints {
			if endpoint.Conditions.Ready != nil && !*endpoint.Conditions.Ready {
				continue
			}

			for _, addr := range endpoint.Addresses {
				weight := 1.0
				if c.metrics != nil && endpoint.NodeName != nil {
					metric := c.metrics.Query(*endpoint.NodeName)
					if nm, ok := metric.(*metrics.NodeExporterNodeMetric); ok {
						weight = nm.AvailableRate()
					}
				}

				pods = append(pods, podState{
					IP:      addr,
					Port:    portStr,
					Weight:  weight,
					Healthy: true,
				})
			}
		}
	}

	totalWeight := 0.0
	for _, p := range pods {
		totalWeight += p.Weight
	}
	if totalWeight > 0 {
		for i := range pods {
			pods[i].Weight /= totalWeight
		}
	} else if len(pods) > 0 {
		for i := range pods {
			pods[i].Weight = 1.0 / float64(len(pods))
		}
	}

	return pods
}

// commitServiceState 将 Service 的状态信息写入 eBPF Maps 中，包括服务的 ClusterIP、端口和后端 Pod 列表。
func (c *Controller) commitServiceState(key, svcIP, svcPort string, pods []podState) {
	// 先删除旧的服务状态，避免数据不一致问题
	hadState := false
	if svcState, exist := c.svcStates[key]; exist {
		hadState = true
		c.bpfProg.AutoDeleteService(bpf.Service{
			IP:   svcState.IP,
			Port: svcState.Port,
		})
	}

	// 如果没有后端 Pod，则直接删除服务状态并返回
	if len(pods) == 0 {
		delete(c.svcStates, key)
		if hadState {
			slog.Info("Service removed from eBPF due to empty backends", "service", key)
		}
		return
	}

	// 根据是否启用 metrics 选择不同的 eBPF Action
	action := bpf.DefaultAction
	if c.metrics != nil {
		action = bpf.WeightedAction
	}

	var backendList []bpf.Backend
	for _, pod := range pods {
		if pod.Healthy {
			backendList = append(backendList, bpf.Backend{IP: pod.IP, Port: pod.Port, Possibility: pod.Weight})
		}
	}
	c.bpfProg.AutoInsertService(bpf.Service{IP: svcIP, Port: svcPort}, backendList, action)

	c.svcStates[key] = &serviceState{
		IP:   svcIP,
		Port: svcPort,
		Pods: pods,
	}
	slog.Info("Service synced to eBPF", "service", key, "backends", len(pods))
}

func serviceStateEqual(a, b *serviceState) bool {
	if a == nil || b == nil {
		return a == b
	}

	if a.IP != b.IP || a.Port != b.Port || len(a.Pods) != len(b.Pods) {
		return false
	}

	for i := range a.Pods {
		if !podStateEqual(a.Pods[i], b.Pods[i]) {
			return false
		}
	}

	return true
}

func podStateEqual(a, b podState) bool {
	return a.IP == b.IP &&
		a.Port == b.Port &&
		a.Healthy == b.Healthy &&
		math.Abs(a.Weight-b.Weight) < 1e-9
}
