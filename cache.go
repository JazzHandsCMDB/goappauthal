package goappauthal

/*
 *
 */

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"io/ioutil"
	"os"
	"syscall"
	"time"
)

type CachedAuth struct {
	Auth   map[string]string `json:"auth"`
	Expire time.Time         `json:"expired_whence"; omitempty"`
}

func (c *CachedAuth) UnmarshalJSON(data []byte) error {
	raw := make(map[string]interface{})

	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	c.Auth = make(map[string]string)
	auth := raw["auth"].(map[string]interface{})
	for k, rawv := range auth {
		v := rawv.(string)
		c.Auth[k] = v
	}

	rawwhence := raw["expired_whence"]
	if fwhence, ok := rawwhence.(float64); ok {
		whence := int64(fwhence)
		c.Expire = time.Unix(whence, 0)
	}
	return nil
}

func (c CachedAuth) MarshalJSON() ([]byte, error) {
	out := make(map[string]interface{})

	out["auth"] = c.Auth
	out["expired_whence"] = c.Expire.Unix()

	by, err := json.Marshal(out)
	return by, err
}

/*
 * determine if the directory is not a symlink, is owned by the uid running
 * this and it's writable only by them
 *
 * returns nil on ok and error otherwise
 */
func isDirSane(path string) error {
	if info, err := os.Lstat(path); err != nil {
		return err
	} else {
		if info.Mode()&os.ModeSymlink == 0 {
			if stat, ok := info.Sys().(*syscall.Stat_t); ok {
				if int(stat.Uid) != int(os.Getuid()) {
					return fmt.Errorf("Ownership of directory is not correct")
				}

				if info.Mode().Perm() != 0700 {
					return fmt.Errorf("Permissions of directory are not correct")
				} else {
					// looks ok
					return nil
				}
			} else {
				return fmt.Errorf("Can not stat directory")
			}
		} else {
			return fmt.Errorf("Cache directory cannot be a symlink")
		}
	}
	return fmt.Errorf("File Permissions were incorrectg")
}

/*
 * figure out the best cache directory.  /run or /tmp
 */
func getCacheDir() (string, error) {
	var c string
	myuid := fmt.Sprintf("%d", os.Getuid())
	if info, err := os.Stat("/run/user/" + myuid); err == nil {
		if info.IsDir() {
			cachedir := "/run/user/" + myuid + "jazzhands-appauthal-cache"
			if err := os.Mkdir(cachedir, os.FileMode(0700)); err != nil {
				if errors.Is(err, fs.ErrExist) {
					c = cachedir
				}
			} else {
				c = cachedir
			}
		}
	}

	if c != "" {
		if err := isDirSane(c); err == nil {
			return c, nil
		}
	}

	cachedir := "/tmp/__jazzhands-appauthal-cache__-" + myuid
	if _, err := os.Stat(cachedir); err == nil {
		if err := isDirSane(cachedir); err == nil {
			return cachedir, nil
		}
	} else {
		if err := os.Mkdir(cachedir, os.FileMode(0700)); err != nil {
			if !errors.Is(err, fs.ErrExist) {
				return "", err
			}

			if err := isDirSane(cachedir); err == nil {
				return cachedir, nil
			} else {
				return "", err
			}
		}
	}
	return "", fmt.Errorf("Unable to find a suitable cachedir")
}

func putCachedAuth(method AppAuthMethod, entry AppAuthAuthEntry, defaultExpiration time.Duration) error {
	pid := fmt.Sprintf("%d", os.Getpid())

	cachedir, err := getCacheDir()
	if err != nil {
		return err
	}

	key := method.BuildCacheKey(entry)
	if key == "" {
		return fmt.Errorf("No Cache Key")
	}

	cachefile := cachedir + string(os.PathSeparator) + key

	expire := entry.GetExpiration()
	if expire.IsZero() {
		now := time.Now()
		expire = now.Add(defaultExpiration)
		fmt.Printf("+++ adding %s and getting %s\n", defaultExpiration, expire)
	}

	m, e := entry.BuildAuthenticateMap()
	if e != nil {
		return e
	}

	cache := CachedAuth{Auth: m, Expire: expire}

	json, err := json.Marshal(cache)
	if err != nil {
		return err
	}

	tmpfile := cachefile + "." + string(pid)
	if fh, err := os.OpenFile(tmpfile, os.O_CREATE|os.O_WRONLY, 0400); err == nil {
		fh.Write(json)
		fh.Write([]byte("\n"))
		fh.Close()

		var stashfile string
		if _, err := os.Stat(cachefile); errors.Is(err, os.ErrNotExist) {
			if e := os.Rename(tmpfile, cachefile); e != nil {
				os.Remove(tmpfile)
				return e
			}
			return nil
		}

		stashfile = cachefile + ".stash" + string(pid)
		// ignoring errors on these three
		os.Rename(cachefile, stashfile)
		os.Rename(tmpfile, cachefile)
		os.Remove(stashfile)
		return nil
	} else {
		return err
	}

	return fmt.Errorf("Cache Write reached theoretically unreachable code")
}

func getCachedAuth(method AppAuthMethod, entry AppAuthAuthEntry) (CachedAuth, error) {
	var empty CachedAuth
	cachedir, err := getCacheDir()
	if err != nil {
		return empty, err
	}

	key := method.BuildCacheKey(entry)
	if key == "" {
		return empty, fmt.Errorf("No Cache Key")
	}

	cachefile := cachedir + string(os.PathSeparator) + key
	if fh, err := os.Open(cachefile); err != nil {
		return empty, err
	} else {
		defer fh.Close()

		injson, err := ioutil.ReadAll(fh)
		if err != nil {
			return empty, err
		}

		var cache CachedAuth
		if e := json.Unmarshal(injson, &cache); e == nil {
			return cache, nil
		} else {
			// failed to parse
			return cache, e
		}
	}

	// should never be reached
	return empty, fmt.Errorf("End of Function Reached, which should not ahppen")
}
