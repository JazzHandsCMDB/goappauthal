package goappauthal

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
