package controller

import (
	"log/slog"
	"runtime"
	"strconv"
	"time"

	"github.com/kerolt/traffic-manager/pkg/bpf"
	"github.com/kerolt/traffic-manager/pkg/metrics"
	discovery1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/labels"
	k8s "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

func NewController(clientSet *k8s.Clientset, bpfProgram *bpf.Program, metricsAddr string) *Controller {
	factory := newSharedInformerFactory(clientSet)
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

	if metricsAddr != "" {
		c.metrics = &metrics.NodeExporterClusterMetrics{Address: metricsAddr}
	}

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

func (c *Controller) Run(stopCh <-chan struct{}) error {
	c.informerFactory.Start(stopCh)
	cache.WaitForCacheSync(stopCh, c.svcSynced, c.epSynced)

	workerCount := runtime.NumCPU()
	if workerCount < 1 {
		workerCount = 1
	}
	for range workerCount {
		go c.runWorker()
	}

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
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}

	svc, err := c.svcLister.Services(namespace).Get(name)
	if err != nil {
		c.mutex.Lock()
		defer c.mutex.Unlock()

		if state, exist := c.svcStates[key]; exist {
			c.bpfProg.AutoDeleteService(bpf.Service{
				IP:   state.IP,
				Port: state.Port,
			})
			delete(c.svcStates, key)
		}

		slog.Debug("delete service data from eBPF", "service", key)
		return nil
	}

	if svc.Spec.ClusterIP == "None" || len(svc.Spec.Ports) == 0 {
		return nil
	}

	selector := labels.SelectorFromSet(labels.Set{discovery1.LabelServiceName: name})
	endpointSlices, err := c.epLister.EndpointSlices(namespace).List(selector)
	if err != nil {
		return err
	}

	podStates := c.buildPodStates(endpointSlices, strconv.Itoa(int(svc.Spec.Ports[0].Port)))

	c.mutex.Lock()
	defer c.mutex.Unlock()

	if oldState, exist := c.svcStates[key]; exist {
		newState := &serviceState{
			IP:   svc.Spec.ClusterIP,
			Port: strconv.Itoa(int(svc.Spec.Ports[0].Port)),
			Pods: podStates,
		}
		if serviceStateEqual(oldState, newState) {
			return nil
		}
	}

	c.commitServiceState(key, svc.Spec.ClusterIP, strconv.Itoa(int(svc.Spec.Ports[0].Port)), podStates)
	return nil
}

// syncLoop 定期触发所有服务的状态刷新，确保 eBPF 中的数据与 Kubernetes 集群状态保持一致。
func (c *Controller) syncLoop(stopCh <-chan struct{}) {
	if c.metrics == nil {
		<-stopCh
		return
	}

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

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
