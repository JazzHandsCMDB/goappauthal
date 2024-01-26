package goappauthal

/*
 *
 */

import (
	"fmt"
	"time"
)

/*
 * Returns a handle to whatever, intellegently trying to do cached logins,
 * including properly attempting to ahndle expiration.  Tries super hard to
 * get signed in and cache credentials if appropriate.
 *
 * optmap - the options section of a dbauth file.
 * entry - a relevant entry to attempt to login .
 * callback - function that will return a login or error
 * state - state for passing back to callback
 */

type AppAuthALLoginCallBack func(map[string]string, any) (any, error)

func DoCachedLogin(optmap map[string]interface{}, entry map[string]interface{}, callback AppAuthALLoginCallBack, state any) (any, error) {
	if entry == nil {
		return nil, fmt.Errorf("No entry")
	}
	method, ok := entry["Method"].(string)
	if !ok {
		return nil, fmt.Errorf("Method is not a valid string")
	}
	methodops := optmap[method]

	var appauth AppAuthAuthEntry
	h, e := GetMethod(method)
	if e != nil {
		e := fmt.Errorf("Unknown or Unloaded method %s", method)
		return nil, e
	}

	/*
	 * This does what it takes to get back an AppAuthAL entry that can
	 * be used by the caller.   It contains a bunch of key/values that
	 * enable loging in.
	 *
	 * for password type, it would just pass things through, for more
	 * complicated ones (like a secrets management system) it may need
	 * to do more complicated things.
	 */

	if e := h.Initialize(methodops, optmap); e != nil {
		return nil, e
	} else {
		if a, err := h.BuildAppAuthAL(entry); err == nil {
			appauth = a
		} else {
			return nil, err
		}
	}

	CachingDisabled := false
	if v, ok := optmap["Caching"]; ok {
		v := v.(bool)
		CachingDisabled = !v
	}

	/*
	 * if there's no point in trying to cache, don't.
	 */
	if CachingDisabled || !h.ShouldCache() {
		xlate, e := appauth.BuildAuthenticateMap()
		if e != nil {
			return nil, e
		}
		return callback(xlate, state)
	}

	/*
	 * This is basically what happens here
	 * 1 fetch catched creds
	 * 2 if success unexpired, try those
	 * 3 if sucesssful conn, return
	 * 4 get new credentials from Vault
	 * 5 if new ones, try them
	 * 6 if cached ones success, and caches diff, save in cache, return
	 * 7 if new ones fail and cached exist, try
	 * 8 if cached ones suceeded, return
	 * 9 if cached ones failed, return failure
	 *
	 */

	// 1, 2, 3
	var cachedcreds CachedAuth
	if c, err := getCachedAuth(h, appauth); err == nil {
		cachedcreds = c
		handle, err := callback(c.Auth, state)
		if err == nil {
			now := time.Now()
			if c.Expire.After(now) {
				return handle, nil
			}
			// otherwise, credentials are expired, but keep just in case
		}
	}

	// 4, 5
	xlate, e := appauth.BuildAuthenticateMap()
	if e != nil {
		return nil, e
	}
	handle, err := callback(xlate, state)
	if err == nil {
		// 6
		defexpsec := int64(86400)
		if rawval, ok := optmap["DefaultCacheExpiration"]; ok {
			fval := rawval.(float64)
			val := int64(fval)
			defexpsec = val
		}
		if rawval, ok := optmap["DefaultCacheDivisor"]; ok {
			fval := rawval.(float64)
			divisor := int64(fval)
			defexpsec = int64(defexpsec / divisor)
		}

		defexp, e := time.ParseDuration(fmt.Sprintf("%ds", defexpsec))
		if e == nil {
			putCachedAuth(h, appauth, defexp)
			// XXX probably want to make this available somehow
			// if e := putCachedAuth(h, appauth, defexp); e !=  nil {
			// 	fmt.Println("cache fail: ", e)
			// }
		}
		return handle, nil
	}

	// 7, 8
	if newhandle, err := callback(cachedcreds.Auth, state); err == nil {
		return newhandle, err
	}

	// 9
	return nil, err
}

/*

	# step 4
	my $newauth = $v->fetch_and_merge_dbauth($auth);

	# 5 if new ones, try them
	# 6 if cached ones success, and caches diff, save in cache, return
	if ($newauth) {
		if ( $conn = &$callback( $args, $newauth ) ) {
			my $new_cache = _assemble_cache( $options, $newauth );

			if ( _diff_cache( $cached, $new_cache->{'auth'} ) ) {
				save_cached( $options, $a, $newauth,
					sub { $v->build_cache_key(@_) } );
			}
			return $conn;
		}
	}

	# 7 if new ones fail and cached exist, try
	# 8 if cached ones suceeded, return
	if ($cached) {
		if ( $conn = &$callback( $args, $cached ) ) {
			return $conn;
		}
	}

	# 9 if cached ones failed, return failure
}

*/
