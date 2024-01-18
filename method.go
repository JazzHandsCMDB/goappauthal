package goappauthal

import (
	"fmt"
	"sync"
)

type AppAuthMethod interface {
	GetName() string
	ShouldCache() bool
	Initialize(interface{}, map[string]interface{}) error
	BuildAppAuthAL(interface{}) (AppAuthAuthEntry, error)
	BuildCacheKey(AppAuthAuthEntry) string
}

var (
	mutex   sync.Mutex
	methods = make(map[string]AppAuthMethod)
)

func RegisterMethod(name string, helper AppAuthMethod) {
	mutex.Lock()
	methods[name] = helper
	mutex.Unlock()
}

func GetMethod(name string) (AppAuthMethod, error) {
	mutex.Lock()
	rv, e := methods[name]
	mutex.Unlock()
	if !e {
		return nil, fmt.Errorf("Unknown helper %s", name)
	}
	return rv, nil
}
