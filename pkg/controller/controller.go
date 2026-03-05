package controller

import (
	"errors"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/kerolt/traffic-manager/pkg/bpf"
	"github.com/kerolt/traffic-manager/pkg/metrics"
	discovery1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	k8s "k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	discoverylisters "k8s.io/client-go/listers/discovery/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

// Controller 负责监听 Kubernetes Service 和 Endpoints 资源的变化，并将服务和后端信息写入 eBPF Maps 中以实现透明化负载均衡。
type Controller struct {
	// TODO: client, bpf, informer/lister/synced, queue, metrics, activeServices, mu
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

// 2) constructor
func NewController(clientSet *k8s.Clientset, bpfProgram *bpf.Program, metricsAddr string) *Controller {
	// 初始化 Kubernetes Informer Factory 和对应的 Service、EndpointSlice Informer/Lister
	factory := informers.NewSharedInformerFactory(clientSet, time.Minute*10)
	svcInformer := factory.Core().V1().Services()
	epInformer := factory.Discovery().V1().EndpointSlices()

	c := &Controller{
		bpfProg:         bpfProgram,
		clients:         clientSet,
		informerFactory: factory,
		svcLister:       svcInformer.Lister(),
		epLister:        epInformer.Lister(),
		queue:           workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]()),
		svcStates:       make(map[string]*serviceState),
		svcSynced:       svcInformer.Informer().HasSynced,
		epSynced:        epInformer.Informer().HasSynced,
	}

	// 如果提供了 metricsAddr，则初始化 ClusterMetric 实例，用于后续查询 Node 的指标数据以计算权重
	if metricsAddr != "" {
		c.metrics = &metrics.NodeExporterClusterMetrics{Address: metricsAddr}
	}

	// 注册 Service 和 EndpointSlice 的事件处理函数
	_, err := svcInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.handleServiceAdd,
		UpdateFunc: c.handleServiceUpdate,
		DeleteFunc: c.handleServiceDelete,
	})
	if err != nil {
		panic(err)
	}

	_, err = epInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.handleEndpointsAdd,
		UpdateFunc: c.handleEndpointsUpdate,
		DeleteFunc: c.handleEndpointsDelete,
	})
	if err != nil {
		panic(err)
	}

	return c
}

// 3) run loop
func (c *Controller) Run(stopCh <-chan struct{}) error {
	c.informerFactory.Start(stopCh)

	cache.WaitForCacheSync(stopCh, c.svcSynced, c.epSynced)

	// 启动多个 worker 来处理队列中的事件，确保能够及时响应 Kubernetes 中的资源变化并更新 eBPF 中的状态
	for range 3 {
		go c.runWorker()
	}

	// 启动一个独立的 goroutine 来执行周期性的全量同步
	// 确保 eBPF 中的状态与 Kubernetes 中的实际状态保持一致
	go c.syncLoop(stopCh)

	<-stopCh
	c.queue.ShutDown()

	return nil
}

func (c *Controller) runWorker() {
	processNextWorkItem := func() bool {
		key, shutdown := c.queue.Get()
		if shutdown {
			return false
		}

		err := c.refreshState(key)
		if err != nil {
			// 处理失败时采用退避重试
			c.queue.AddRateLimited(key)
			slog.Error("error syncing key, requeuing", "key", key, "error", err)
		} else {
			c.queue.Forget(key)
		}

		return true
	}

	for processNextWorkItem() {
	}
}

func (c *Controller) refreshState(key string) error {
	// 获取 Service 的 namespace 和 name
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}

	// 从 lister 中获取对应的 Service 对象
	svc, err := c.svcLister.Services(namespace).Get(name)
	if err != nil {
		// 如果 Service 不存在，说明它被删除了，需要清理 eBPF 中的状态
		c.mutex.Lock()
		defer c.mutex.Unlock()

		if state, exist := c.svcStates[key]; exist {
			c.bpfProg.AutoDeleteService(bpf.Service{
				IP:   state.IP,
				Port: state.Port,
			}, nil)
			delete(c.svcStates, key)
		}

		slog.Debug("delete service data from eBPF", "service", key)

		return nil
	}

	// 对于 ClusterIP 类型的 Service，如果没有有效的 ClusterIP 或者没有定义端口，则不需要在 eBPF 中维护状态，直接返回即可。
	if svc.Spec.ClusterIP == "None" || len(svc.Spec.Ports) == 0 {
		return nil
	}

	// 从 lister 中获取与 Service 相关的 EndpointSlice 列表
	selector := labels.SelectorFromSet(labels.Set{
		discovery1.LabelServiceName: name,
	})
	endpointSlices, err := c.epLister.EndpointSlices(namespace).List(selector)
	if err != nil {
		return err
	}

	// 构建后端 Pod 的状态列表，包括 IP、端口、权重和健康状态
	// 根据 EndpointSlice 中的地址信息以及 Service 定义的端口来确定后端 Pod 的访问信息
	podStates := c.buildPodStates(endpointSlices, strconv.Itoa(int(svc.Spec.Ports[0].Port)))

	// 提交服务状态到 eBPF，并更新 svcStates
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.commitServiceState(key, svc.Spec.ClusterIP, strconv.Itoa(int(svc.Spec.Ports[0].Port)), podStates)

	return nil
}

func (c *Controller) syncLoop(stopCh <-chan struct{}) {
	// 每 10 秒执行一次全量同步，确保 eBPF 中的状态与 Kubernetes 中的实际状态保持一致。这对于处理漏掉的事件或修复不一致状态非常重要。
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	// 在每次周期性同步时，如果启用了 metrics，还会更新指标数据，以便 eBPF 程序能够根据最新的指标进行加权负载均衡。
	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			if c.metrics != nil {
				if err := c.metrics.Update(); err != nil {
					slog.Warn("Failed to update metrics", "error", err)
				}
			}

			c.mutex.Lock()
			for key := range c.svcStates {
				c.queue.Add(key)
			}
			c.mutex.Unlock()
		}
	}
}

func (c *Controller) handleServiceAdd(obj any) {
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		slog.Error("Failed to get key from service object", "error", err)
		return
	}
	c.queue.Add(key)
}

func (c *Controller) handleServiceUpdate(oldObj, newObj any) {
	key, err := cache.MetaNamespaceKeyFunc(newObj)
	if err != nil {
		slog.Error("Failed to get key from updated service object", "error", err)
		return
	}
	c.queue.Add(key)
}

func (c *Controller) handleServiceDelete(obj any) {
	key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
	if err != nil {
		slog.Error("Failed to get key from deleted service object", "error", err)
		return
	}
	c.queue.Add(key)
}

func (c *Controller) handleEndpointsAdd(obj any) {
	key, err := serviceKeyFromEndpointSliceObj(obj)
	if err != nil {
		slog.Error("Failed to get key from endpoints object", "error", err)
		return
	}
	c.queue.Add(key)
}

func (c *Controller) handleEndpointsUpdate(oldObj, newObj any) {
	key, err := serviceKeyFromEndpointSliceObj(newObj)
	if err != nil {
		slog.Error("Failed to get key from updated endpoints object", "error", err)
		return
	}
	c.queue.Add(key)
}

func (c *Controller) handleEndpointsDelete(obj any) {
	key, err := serviceKeyFromEndpointSliceObj(obj)
	if err != nil {
		slog.Error("Failed to get key from deleted endpoints object", "error", err)
		return
	}
	c.queue.Add(key)
}

func serviceKeyFromEndpointSliceObj(obj any) (string, error) {
	getKey := func(slice *discovery1.EndpointSlice) (string, error) {
		// 从 EndpointSlice 的 label 中获取对应的 Service 名称
		serviceName, ok := slice.Labels[discovery1.LabelServiceName]
		if !ok || serviceName == "" {
			return "", errors.New("endpointslice missing service-name label")
		}

		return slice.Namespace + "/" + serviceName, nil
	}

	// 直接处理 EndpointSlice 对象
	if endpointSlice, ok := obj.(*discovery1.EndpointSlice); ok {
		return getKey(endpointSlice)
	}

	// 如果是删除事件，obj 可能是一个 tombstone，需要从中提取 EndpointSlice 对象
	tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
	if !ok {
		return "", errors.New("object is not EndpointSlice or tombstone")
	}

	endpointSlice, ok := tombstone.Obj.(*discovery1.EndpointSlice)
	if !ok {
		return "", errors.New("tombstone object is not EndpointSlice")
	}

	return getKey(endpointSlice)
}

func (c *Controller) buildPodStates(endpointSlices []*discovery1.EndpointSlice, svcPort string) []podState {
	var pods []podState

	for _, endpointSlice := range endpointSlices {
		portStr := svcPort
		if len(endpointSlice.Ports) > 0 && endpointSlice.Ports[0].Port != nil {
			portStr = strconv.Itoa(int(*endpointSlice.Ports[0].Port))
		}

		for _, endpoint := range endpointSlice.Endpoints {
			for _, addr := range endpoint.Addresses {
				if !checkHealth(addr, portStr) {
					continue
				}

				weight := 1.0
				if c.metrics != nil && endpoint.NodeName != nil {
					// 如果启用了 metrics，并且 Endpoint 关联了 Node，则根据 Node 的指标计算权重
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

	// 归一化权重，确保它们的总和为 1，以便 eBPF 程序能够正确地进行加权负载均衡
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

func (c *Controller) commitServiceState(key, svcIP, svcPort string, pods []podState) {
	// 首先清理旧的 eBPF 状态（如果存在），以避免残留的服务或后端信息导致不一致
	if svcState, exist := c.svcStates[key]; exist {
		c.bpfProg.AutoDeleteService(bpf.Service{
			IP:   svcState.IP,
			Port: svcState.Port,
		}, nil)
	}

	// 更新 eBPF 中的服务和后端信息
	if len(pods) > 0 {
		action := bpf.DefaultAction
		if c.metrics != nil {
			action = bpf.WeightedAction
		}

		c.bpfProg.InsertServiceItem(svcIP, svcPort, len(pods), action)

		percetageSum := 0.0
		for i, pod := range pods {
			percetageSum += pod.Weight
			c.bpfProg.AutoInsertBackend(svcIP, svcPort, pod.IP, pod.Port, i+1, pod.Weight, percetageSum)
		}
	}

	// 更新 svcStates 中的状态以供后续比较和删除
	c.svcStates[key] = &serviceState{
		IP:   svcIP,
		Port: svcPort,
		Pods: pods,
	}
	slog.Info("Synced service", "service", key, "backends", len(pods))
}

// checkHealth 通过尝试建立 TCP 连接来检查后端 Pod 的健康状态。
// 如果连接成功，则认为该后端是健康的；如果连接失败，则认为该后端不可用，不会被添加到 eBPF 中。
func checkHealth(ip, port string) bool {
	addr := net.JoinHostPort(ip, port)

	conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
	if err != nil {
		return false
	}

	// 网络的错误不应该导致panic，所以这里记录日志但不返回错误
	err = conn.Close()
	if err != nil {
		slog.Error("Failed to close connection during health check", "address", addr, "error", err)
	}

	return true
}
