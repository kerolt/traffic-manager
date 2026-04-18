package controller

import (
	"errors"
	"log/slog"

	discovery1 "k8s.io/api/discovery/v1"
	"k8s.io/client-go/tools/cache"
)

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
		serviceName, ok := slice.Labels[discovery1.LabelServiceName]
		if !ok || serviceName == "" {
			return "", errors.New("endpointslice missing service-name label")
		}
		return slice.Namespace + "/" + serviceName, nil
	}

	if endpointSlice, ok := obj.(*discovery1.EndpointSlice); ok {
		return getKey(endpointSlice)
	}

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
