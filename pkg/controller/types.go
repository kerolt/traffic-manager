package controller

import (
	"sync"
	"time"

	"github.com/kerolt/traffic-manager/pkg/bpf"
	"github.com/kerolt/traffic-manager/pkg/metrics"
	"k8s.io/client-go/informers"
	k8s "k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	discoverylisters "k8s.io/client-go/listers/discovery/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

// Controller 负责监听 Kubernetes Service 和 Endpoints 资源的变化，并将服务和后端信息写入 eBPF Maps 中以实现透明化负载均衡。
type Controller struct {
	bpfProg *bpf.Program

	clients *k8s.Clientset

	metrics metrics.ClusterMetric

	informerFactory informers.SharedInformerFactory
	svcLister       corelisters.ServiceLister
	epLister        discoverylisters.EndpointSliceLister

	queue workqueue.TypedRateLimitingInterface[string]

	svcSynced cache.InformerSynced
	epSynced  cache.InformerSynced

	svcStates map[string]*serviceState

	mutex sync.Mutex
}

// serviceState 代表一个 Service 的状态信息，包括 ClusterIP、端口和后端 Pod 列表。
type serviceState struct {
	IP   string
	Port string
	Pods []podState
}

// podState 代表一个后端 Pod 的状态信息，包括 IP、端口、权重和健康状态。
type podState struct {
	IP      string
	Port    string
	Weight  float64
	Healthy bool
}

func newSharedInformerFactory(clientSet *k8s.Clientset) informers.SharedInformerFactory {
	return informers.NewSharedInformerFactory(clientSet, time.Minute*10)
}
