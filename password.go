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

//
// generic (basic, copy around) interface for dealing with passwords
//

import (
	// 	"fmt"
	"time"
)

// This must match type AppAuthMethod interface
type AppAuthPasswordMethod struct {
	options       map[string]string
	isInitialized bool
}

// This must match type AppAuthAuthEntry interface
type AppAuthPasswordEntry struct {
	authent map[string]string
}

// Register that I exist with AppAuthAL
func init() {
	var a AppAuthPasswordMethod

	RegisterMethod("password", &a)
}

// returns the name of the method, for sanity reasons
func (a *AppAuthPasswordMethod) GetName() string {
	return ("password")
}

// indicates if it makes any sense to cache these values
func (a *AppAuthPasswordMethod) ShouldCache() bool {
	return false
}

// unnecessary if caching is not implemented
func (a *AppAuthPasswordMethod) BuildCacheKey(entry AppAuthAuthEntry) string {
	return ""
}

func (a *AppAuthPasswordMethod) Initialize(inmap interface{}, globals map[string]interface{}) error {
	a.isInitialized = true

	// consider how to process options
	// m := inmap.(map[string]interface{})

	// deal with doubles that aren't supposed to exist
	return nil
}

// convert the basic structure to something that can be used by the db
// connector, this is basically a copy since password is the simpliest of
// connection methods
func (a *AppAuthPasswordMethod) BuildAppAuthAL(inmap interface{}) (AppAuthAuthEntry, error) {
	var entry AppAuthPasswordEntry
	entry.authent = make(map[string]string)

	pwmap := inmap.(map[string]interface{})
	for k, v := range pwmap {
		entry.authent[k] = v.(string)
	}

	return &entry, nil
}

// entry
func (a *AppAuthPasswordEntry) BuildAuthenticateMap() (map[string]string, error) {
	return a.authent, nil
}

func (a *AppAuthPasswordEntry) GetExpiration() time.Time {
	life := 86400
	dur, _ := time.ParseDuration(string(life) + "s")
	now := time.Now()
	return now.Add(dur)
}
