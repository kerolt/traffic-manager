package bpf

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strconv"

	"github.com/cilium/cilium/pkg/u8proto"
	"github.com/cilium/ebpf"
)

func LookupPinnedService(serviceIP string, servicePort string) (bool, *ServiceEntry, error) {
	parsedIP := net.ParseIP(serviceIP)
	if parsedIP == nil {
		return false, nil, fmt.Errorf("invalid service IP: %s", serviceIP)
	}

	servicePortInt, err := strconv.Atoi(servicePort)
	if err != nil {
		return false, nil, fmt.Errorf("invalid service port: %w", err)
	}

	servicesMap, err := ebpf.LoadPinnedMap(filepath.Clean(ServiceMapPinPath), nil)
	if err != nil {
		return false, nil, err
	}
	defer servicesMap.Close()

	for _, scope := range []uint8{1, 0} {
		serviceKey := NewServiceKey(parsedIP, uint16(servicePortInt), u8proto.ANY, scope)
		serviceValue := NewServiceMeta(0, DefaultAction, 0)

		err := servicesMap.Lookup(serviceKey.ToNetwork(), serviceValue)
		if err == nil {
			return true, serviceValue.ToHost(), nil
		}
		if !errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, nil, err
		}
	}

	return false, nil, nil
}

func ReadPinnedStats() (TrafficStats, error) {
	statsMap, err := ebpf.LoadPinnedMap(filepath.Clean(StatsMapPinPath), nil)
	if err != nil {
		return TrafficStats{}, err
	}
	defer statsMap.Close()

	readStat := func(index uint32) (uint64, error) {
		var value uint64
		if err := statsMap.Lookup(index, &value); err != nil {
			return 0, err
		}
		return value, nil
	}

	stats := TrafficStats{}
	if stats.ConnectAttempts, err = readStat(statConnectAttempts); err != nil {
		return TrafficStats{}, err
	}
	if stats.ServiceMisses, err = readStat(statServiceMiss); err != nil {
		return TrafficStats{}, err
	}
	if stats.BackendSlotMisses, err = readStat(statBackendSlotMiss); err != nil {
		return TrafficStats{}, err
	}
	if stats.BackendMisses, err = readStat(statBackendMiss); err != nil {
		return TrafficStats{}, err
	}
	if stats.RewriteSuccesses, err = readStat(statRewriteSuccess); err != nil {
		return TrafficStats{}, err
	}
	if stats.UnsupportedAction, err = readStat(statUnsupportedAction); err != nil {
		return TrafficStats{}, err
	}

	return stats, nil
}
