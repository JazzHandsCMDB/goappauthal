package goappauthal

/*
 * Copyright (c) 2024 Todd M. Kover
 *
 * All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
