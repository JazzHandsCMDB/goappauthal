/*
govault exists primarily to support vault in AppAuthAL files, but it is
possible to use it for rudimentary interactions with Hasicorp Vault.

This caches credentials in a way that is compatible with the perl
and python appauthal libraries which allows for clients to continue to
work without connectivity to vault for periods of time.

The Hashicorp Vault Client LIbrary is probably a better choice unless you
have a specific reason to use this one.  It is almost certainly better.

A minimal example is:

	   {
		"options": {
			"vault": {
				"CAPath": "/usr/pkg/etc/openssl/certs",
				"VaultServer": "https://vault.example.com:8200",
				"VaultRoleId": "e3a17f50-6aea-15df-93f3-cc1651dcb4d9",
				"VaultSecretIdPath": "/var/lib/vault/stab/secret-id"
			}
		},
		"database": {
			"Method": "vault",
			"VaultPath": "kv/data/myfirstapp/db",
			"import": {
				"DBType": "postgresql",
				"Method": "password",
				"DBHost": "jazzhands-db.example.com",
				"DBName": "jazzhands"
			},
			"map": {
				"Username": "username",
				"Password": "password"
			}
		}
	  }
*/
package govault

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
	"time"
)

// our $ttl_refresh_seconds = 3600 / 2;

// An AppAuthVaultAuthEntry is an implementation of the
// goappauthal.AppAuthAuthEntry interface.  It is basically a processed version
// of one entry where method = 'Vault' in an appauthal file.
type AppAuthVaultAuthEntry struct {
	method     *AppAuthVaultMethod
	path       string
	imp        map[string]string
	xlate      map[string]string
	expiration time.Time
	cache      map[string]string
	haveCache  bool
}

func (a *AppAuthVaultAuthEntry) BuildAuthenticateMap() (map[string]string, error) {
	rv := make(map[string]string)

	if a.haveCache {
		return a.cache, nil
	}

	metadata, e := a.method.VaultReadRaw(a.path)
	if e != nil {
		return nil, fmt.Errorf("VaultReadRaw(%s): %e", a.path, e)
	}

	vaultentry, e := a.method.ExtractVaultKV(metadata)
	if e != nil {
		return nil, fmt.Errorf("ExtractVaultKV(): %e", e)
	}

	//
	// map fields from vault
	//
	for key, val := range a.xlate {
		rv[key] = vaultentry[val]
	}

	//
	// copy over all the imports
	//
	for key, val := range a.imp {
		rv[key] = val
	}

	//
	if raw, ok := metadata["lease_duration"]; ok {
		// start renewing three quarters of the way in
		s := raw.(float64) * .75
		dur, e := time.ParseDuration(string(int64(s)) + "s")
		if e == nil && dur != 0 {
			now := time.Now()
			a.expiration = now.Add(time.Second * dur)
		}
	}

	// if we do not provide a lease, the caching magic comes up with one

	// perhaps not the best place for this?
	if a.method.VaultTokenPath == "" {
		a.method.RevokeMyToken()
	}

	a.haveCache = true
	a.cache = rv
	return a.cache, nil
}

func (a *AppAuthVaultAuthEntry) GetExpiration() time.Time {
	return a.expiration
}
