/*
This provides a generic interface to obtaining and using crednetials.  It
is primarily for database credentials but others are possible.

This module is not meant to be directly used by mortals; it is meant to
provide support functions for other libraries that depend on it.

Files are looked for based on /var/lib/jazzhands/appauth-info or the
APPAUTHAL_CONFIG environment variable's config file.  Under that directory,
the library looks for app.json, and if there is an instance involved looks
under app/instance.json and may fall backt to app.json based on
sloppy_instance_match.

The library also implements caching via a generic sign in module, and
will cache credentials under /run/user/uid or in a directory under
/tmp.  If the running user does not own that directory and it's not
other readable, it will not be used.

This caching is done by the DoCachedLogin call.  It is possible to
completely disable Caching but setting Caching to false in the general options
of a given appauthaal file.    The default amount of time to cache a
record is set to 86400 seconds, but can be changed via DefaultCacheExpiration
in the options field.  If the underlying engine (such as vault) includes
a lifetime for a credential, it is cached, by default, for half that time.
The DefaultCacheDivisor option can be used to change that divisor.  There
is no way to override that value, just manipulate it.

The AppAuthAL has a hash of many top level stanzas, interpreted by various
AppAuthLayer consumers.  options is generic across all libraries although
may have some module-specific options.  database is used for DBI.

An example of one:

	{
	      "options": {
	              "Caching": true,
	              "use_session_variables": "yes"
	      },
	      "database": {
	              "DBType": "postgresql",
	              "Method": "password",
	              "DBHost": "jazzhands-db.example.com",
	              "DBName": "jazzhands",
	              "Username": "app_stab",
	              "Password": "thisisabadpassword"
	      }
	}

The global configuration file (defaults to /etc/jazzhands/appauth.json) can
be used to define system wide defaults.  It is optional.

The config file format is JSON.  Here is an example:

	{
	     "onload": {
	             "environment": {
	                     "ORACLE_HOME": "/usr/local/oracle/libs"
	             }
	     },
	     "search_dirs": [
	             ".",
	             "/var/lib/appauthal"
	     ],
	     "sloppy_instance_match": "yes",
	     "use_session_variables": "yes"
	}

The "onload" describes things that happen during the importing of the
AppAuthAL library and are used to setup things that other libraries may
require.  In this case, environment variables required by Oracle.

The search_dirs parameter is used to search for auth files, and defaults to
/var/lib/jazzhands/appauth-info .  It will iterate through listed directories
until it finds a match.  Note that "." means the directory the config file
appears in rather than a literal ".".  This is typically used to stash all
the development connection information in one directory with the config file.

sloppy_instance_match tells the library to use the non-instance version of
files if there is no instance match.

use_session_variables tells the library to try to use session variables
in underlying libraries to set usernames, if this is available.  This is
generally a JazzHands-specific thing for databases, but may work in other
instances.
*/
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
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"
)

type AppAuthALConfig struct {
	Onload              map[string]interface{} `json:"onload";omitempty`
	SearchPath          []string               `json:"search_dirs";omitempty`
	SloppyMatch         string                 `json:"sloppy_instance_match";omitempty`
	UseSessionVariables string                 `json:"use_session_variables;omitempty"`
}

// This is a parsed entry
type AppAuthAuthEntry interface {
	BuildAuthenticateMap() (map[string]string, error)
	GetExpiration() time.Time
}

type appauthalfile struct {
	Options interface{}
}

func findAndReadConfig() (AppAuthALConfig, string, error) {
	var cfg AppAuthALConfig
	var cfgfn string
	var fatalOpenFail bool

	if envfn := os.Getenv("APPAUTHAL_CONFIG"); envfn != "" {
		fatalOpenFail = true

		if _, err := os.Stat(envfn); err != nil {
			return cfg, envfn, err
		}
		cfgfn = envfn
	} else {
		fatalOpenFail = false
		cfgfn = "/etc/jazzhands/appauth-config.json"
	}

	var fh *os.File
	if f, err := os.Open(cfgfn); err == nil {
		fh = f
	} else {
		if fatalOpenFail {
			return cfg, cfgfn, err
		}
		return cfg, cfgfn, nil
	}
	defer fh.Close()

	injson, err := ioutil.ReadAll(fh)
	if err != nil {
		return cfg, cfgfn, err
	}
	if e := json.Unmarshal(injson, &cfg); e != nil {
		return cfg, cfgfn, e
	}

	return cfg, cfgfn, nil
}

// other implementations do app, instance, section, with the second two being
// optional, so just ignoring those for the moment
func FindAndProcessAuth(App string) (interface{}, error) {
	var parsedauth interface{}

	var search []string
	cfg, cfgfn, err := findAndReadConfig()
	if err != nil {
		return parsedauth, err
	}

	if len(cfg.SearchPath) > 0 {
		search = cfg.SearchPath
	} else {
		search = append(search, "/var/lib/jazzhands/appauth-info")
	}

	var foundpath string
	for _, dir := range search {
		if dir == "." {
			dir = filepath.Dir(cfgfn)
		}
		fpath := fmt.Sprintf("%s%c%s.json", dir, os.PathSeparator, App)
		if _, err := os.Stat(fpath); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				// adjust auth to have filename
				return parsedauth, err
			}
		} else {
			foundpath = fpath
			break
		}
	}

	if foundpath == "" {
		return parsedauth, fmt.Errorf("Path not found")
	}

	var fh *os.File
	if f, err := os.Open(foundpath); err == nil {
		fh = f
	} else {
		return parsedauth, nil
	}

	injson, err := ioutil.ReadAll(fh)
	if err != nil {
		return parsedauth, err
	}
	if e := json.Unmarshal(injson, &parsedauth); e != nil {
		return parsedauth, e
	}

	return parsedauth, nil
}
