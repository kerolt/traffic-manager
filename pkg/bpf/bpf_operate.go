package bpf

import (
	"log/slog"
	"math"
	"net"
	"strconv"

	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/u8proto"
	"github.com/cilium/ebpf"
)

type ServiceEndpoint struct {
	IP   string
	Port int
}

type BackendEndpoint struct {
	IP   string
	Port int
}

type ServiceMetaParams struct {
	Service      ServiceEndpoint
	BackendCount int
	Action       Action
	TotalWeight  uint16
}

type BackendSlotParams struct {
	Service               ServiceEndpoint
	Backend               BackendEndpoint
	BackendID             int
	SlotIndex             int
	Possibility           float64
	PossibilityUpperBound float64
}

func parseServiceEndpoint(ip string, port string) (ServiceEndpoint, bool) {
	portInt, err := strconv.Atoi(port)
	if err != nil {
		slog.Error("servicePort parse failed", "error", err)
		return ServiceEndpoint{}, false
	}

	return ServiceEndpoint{IP: ip, Port: portInt}, true
}

func parseBackendEndpoint(ip string, port string) (BackendEndpoint, bool) {
	portInt, err := strconv.Atoi(port)
	if err != nil {
		slog.Error("backendPort parse failed", "error", err)
		return BackendEndpoint{}, false
	}

	return BackendEndpoint{IP: ip, Port: portInt}, true
}

// InsertServiceMeta 将服务元数据插入 Service Meta Map
func (p *Program) InsertServiceMeta(params ServiceMetaParams) bool {
	// ip+port，协议类型（TCP/UDP/ANY），查找范围（Local/Cluster）
	serviceKey := NewServiceKey(net.ParseIP(params.Service.IP), uint16(params.Service.Port), u8proto.ANY, 0)
	// service对应的后端数量，调度策略，权重总和
	serviceValue := NewServiceMeta(uint16(params.BackendCount), params.Action, params.TotalWeight)

	err := p.connectObj.connectMaps.ServiceMetaMap.Update(serviceKey.ToNetwork(), serviceValue.ToNetwork(), ebpf.UpdateAny)
	if err != nil {
		slog.Error("service_meta_map update failed", "error", err)
		return false
	}

	slog.Debug("InsertServiceMeta succeeded",
		"serviceIP", params.Service.IP,
		"servicePort", params.Service.Port,
		"backendNumber", params.BackendCount,
		"totalWeight", params.TotalWeight)
	return true
}

// DeleteServiceMeta 从 Service Meta Map 删除服务
func (p *Program) DeleteServiceMeta(service ServiceEndpoint) bool {
	serviceKey := NewServiceKey(net.ParseIP(service.IP), uint16(service.Port), u8proto.ANY, 0)

	err := p.connectObj.connectMaps.ServiceMetaMap.Delete(serviceKey.ToNetwork())
	if err != nil {
		slog.Error("service_meta_map delete failed", "error", err)
		return false
	}

	return true
}

// DeleteServiceSlot 从 Service Slot Map 删除服务后端槽位
func (p *Program) DeleteServiceSlot(service ServiceEndpoint, slotIndex int) bool {
	serviceKey := NewServiceSlotKey(net.ParseIP(service.IP), uint16(service.Port), u8proto.ANY, 0, uint16(slotIndex))

	err := p.connectObj.connectMaps.ServiceSlotMap.Delete(serviceKey.ToNetwork())
	if err != nil {
		slog.Error("service_slot_map delete failed", "error", err)
		return false
	}

	return true
}

// InsertBackend 将后端信息插入 Service Slot Map (作为槽位) 和 Backend Map (作为详细信息)
func (p *Program) InsertBackend(params BackendSlotParams) bool {
	backendKey := BackendId{uint32(params.BackendID)}
	backendServiceKey := NewServiceSlotKey(net.ParseIP(params.Service.IP), uint16(params.Service.Port), u8proto.ANY, 0, uint16(params.SlotIndex))

	backendServiceValue :=
		NewServiceSlot(
			backendKey,
			Possibility{
				percentage:                  params.Possibility,
				currentPercentageRangeUpper: params.PossibilityUpperBound,
			},
		)

	err := p.connectObj.connectMaps.ServiceSlotMap.Update(backendServiceKey.ToNetwork(), backendServiceValue.ToNetwork(), ebpf.UpdateAny)
	if err != nil {
		slog.Error("service_slot_map update failed", "error", err)
		return false
	}

	backendValue := NewBackendValue(net.ParseIP(params.Backend.IP), uint16(params.Backend.Port), u8proto.ANY, loadbalancer.BackendStateActive)
	err = p.connectObj.connectMaps.BackendMap.Update(backendKey.ID, backendValue.ToNetwork(), ebpf.UpdateAny)
	if err != nil {
		slog.Error("backend_map update failed", "error", err)
		return false
	}

	return true
}

// DeleteBackend 根据全局 BackendID 从 Backend Map 删除条目
func (p *Program) DeleteBackend(backendID int) bool {
	err := p.connectObj.connectMaps.BackendMap.Delete(uint32(backendID))
	if err != nil {
		slog.Error("backend_map delete failed", "error", err)
		return false
	}
	return true
}

// AutoInsertService 自动编排并插入完整的服务及其所属的后端列表
func (p *Program) AutoInsertService(service Service, backendList []Backend, action Action) {
	serviceRef, ok := parseServiceEndpoint(service.IP, service.Port)
	if !ok {
		return
	}

	totalPercentage := 0.0

	// 按照后端列表顺序自动分配槽位索引，插入后端信息到 Service Slot Map 和 Backend Map
	for i, backend := range backendList {
		totalPercentage += backend.Possibility
		p.AutoInsertBackend(serviceRef, backend, i+1, totalPercentage)
	}

	// 插入服务元数据到 Service Meta Map
	p.InsertServiceMeta(ServiceMetaParams{
		Service:      serviceRef,
		BackendCount: len(backendList),
		Action:       action,
		TotalWeight:  uint16(totalPercentage * maxPossibilityUnit),
	})

	// 如果总权重不等于 1，说明配置可能存在问题
	// TODO 进一步处理这种异常情况，例如自动调整权重或标记服务状态
	if math.Abs(totalPercentage-1) > 0.005 {
		slog.Warn("Total weight for service is not 1",
			"serviceIP", service.IP,
			"servicePort", service.Port,
			"totalPercentage", totalPercentage)
	}
}

// AutoDeleteService 自动删除服务及其关联的所有后端资源
func (p *Program) AutoDeleteService(service Service) bool {
	serviceRef, ok := parseServiceEndpoint(service.IP, service.Port)
	if !ok {
		return false
	}

	serviceKey := NewServiceKey(net.ParseIP(serviceRef.IP), uint16(serviceRef.Port), u8proto.ANY, 0)
	serviceValue := NewServiceMeta(0, DefaultAction, 0)

	// 删除 ServiceMetaMap 中的服务条目
	err := p.connectObj.connectMaps.ServiceMetaMap.Lookup(serviceKey.ToNetwork(), serviceValue)
	if err != nil {
		slog.Error("service_meta_map lookup failed", "error", err)
		return false
	}
	p.DeleteServiceMeta(serviceRef)

	// 根据 ServiceMeta 中的后端数量，删除 ServiceSlotMap 中对应的槽位和 BackendMap 中的后端信息
	for i := 1; i <= int(serviceValue.Count); i++ {
		backendServiceKey := NewServiceSlotKey(net.ParseIP(serviceRef.IP), uint16(serviceRef.Port), u8proto.ANY, 0, uint16(i))
		backendServiceValue := NewServiceSlot(BackendId{uint32(0)}, Possibility{0, 0})

		err := p.connectObj.connectMaps.ServiceSlotMap.Lookup(backendServiceKey.ToNetwork(), backendServiceValue)
		if err != nil {
			slog.Warn("service_slot_map lookup failed", "error", err)
			break
		}
		slog.Debug("To delete backend service",
			"backendServiceKey", backendServiceKey.String(),
			"backendServiceValue", backendServiceValue.String())

		p.AutoDeleteBackend(int(backendServiceValue.BackendID.ID))
		p.DeleteServiceSlot(serviceRef, i)
	}

	slog.Debug("AutoDeleteService succeeded",
		"serviceIP", serviceRef.IP,
		"servicePort", serviceRef.Port)
	return true
}

func (p *Program) declareBackendID() int {
	if n := len(p.freeBackendIDs); n > 0 {
		backendID := p.freeBackendIDs[n-1]
		p.freeBackendIDs = p.freeBackendIDs[:n-1]
		p.backEndSet[backendID] = true
		return backendID
	}

	backendID := p.currentIndex
	p.currentIndex++
	p.backEndSet[backendID] = true
	return backendID
}

func (p *Program) releaseBackendID(backendID int) {
	if backendID < 0 {
		return
	}

	if inUse, exists := p.backEndSet[backendID]; exists && inUse {
		p.backEndSet[backendID] = false
		p.freeBackendIDs = append(p.freeBackendIDs, backendID)
	}
}

// AutoInsertBackend 自动声明 BackendID 并将后端节点插入到 BPF Map
func (p *Program) AutoInsertBackend(service ServiceEndpoint, backend Backend, slotIndex int, possibilityUpperBound float64) (bool, int) {
	// 分配一个全局唯一的 backend id
	backendID := p.declareBackendID()

	backendRef, ok := parseBackendEndpoint(backend.IP, backend.Port)
	if !ok {
		p.releaseBackendID(backendID)
		return false, backendID
	}

	ok = p.InsertBackend(BackendSlotParams{
		Service:               service,
		Backend:               backendRef,
		BackendID:             backendID,
		SlotIndex:             slotIndex,
		Possibility:           backend.Possibility,
		PossibilityUpperBound: possibilityUpperBound,
	})
	if ok {
		slog.Debug("AutoInsertBackend succeeded",
			"serviceIP", service.IP,
			"servicePort", service.Port,
			"backendIP", backendRef.IP,
			"backendPort", backendRef.Port,
			"backendID", backendID,
			"slotIndex", slotIndex,
			"possibility", backend.Possibility)
	} else {
		p.releaseBackendID(backendID)
	}
	return ok, backendID
}

// AutoDeleteBackend 从 BPF Map 中删除指定的后端节点
func (p *Program) AutoDeleteBackend(backendID int) bool {
	ok := p.DeleteBackend(backendID)
	if ok {
		p.releaseBackendID(backendID)
		slog.Debug("AutoDeleteBackend succeeded", "backendID", backendID)
	}
	return ok
}
