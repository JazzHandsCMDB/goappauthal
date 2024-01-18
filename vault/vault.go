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
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"github.com/jazzhandscmdb/goappauthal"
	"net/http"
	"os"
	"regexp"
	"strings"
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

// An AppAuthVaultMethod is an implementation of the goappauthal.AppAuthMethod
// interface, and has all the global options processed and initialized when
// talking to vault.
type AppAuthVaultMethod struct {
	CAPath         string
	VaultServer    string
	VaultTokenPath string
	VaultRoleId    string
	VaultSecretId  string
	options        map[string]string
	isInitialized  bool
	token          string
	client         *http.Client
	lease_duration int64
}

// Register that I exist with AppAuthAL
func init() {
	var a AppAuthVaultMethod
	goappauthal.RegisterMethod("vault", &a)
}

// given a filename and value key, must have only one and return the correct
// value (possibly by reading the file)
func findBestValue(m map[string]interface{}, valueKey, fileNameKey string) (string, error) {
	value, verv := m[valueKey].(string)
	fn, fnkeyv := m[fileNameKey].(string)

	if verv && fnkeyv {
		return "", fmt.Errorf("Cannot have both %s and %s", valueKey, fileNameKey)
	}

	if verv {
		return value, nil
	}

	contents, err := os.ReadFile(fn)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(contents)), nil
}

// GetName returns the nmame of the method ("vault")
func (a *AppAuthVaultMethod) GetName() string {
	return "vault"
}

// ShouldCache indicates if it is reasonable to cache credentials from this
// module.   Returns true in this case.
func (a *AppAuthVaultMethod) ShouldCache() bool {
	return true
}

// Does whatever initialization is reqauired from an interface which came
// from an appauthal file.  The "vault" sections of the options stanza.
func (a *AppAuthVaultMethod) Initialize(inmap interface{}, globals map[string]interface{}) error {
	a.isInitialized = true

	if inmap == nil {
		return fmt.Errorf("Empty initialization map submitted")
	}

	m := inmap.(map[string]interface{})

	if val, err := findBestValue(m, "VaultSecretId", "VaultSecretIdPath"); err != nil {
		return err
	} else {
		a.VaultSecretId = val
	}

	if val, err := findBestValue(m, "VaultRoleId", "VaultRoleIdPath"); err != nil {
		return err
	} else {
		a.VaultRoleId = val
	}

	if v, ok := m["CAPath"]; ok {
		a.CAPath = v.(string)
	} else if env := os.Getenv("VAULT_CAPATH"); env != "" {
		a.CAPath = env
	}
	if v, ok := m["VaultTokenPath"]; ok {
		a.VaultTokenPath = v.(string)
	}
	if v, ok := m["VaultServer"]; ok {
		a.VaultServer = v.(string)
	} else {
		a.VaultServer = os.Getenv("VAULT_ADDR")
	}

	if a.VaultServer == "" {
		return fmt.Errorf("Vault Server is not set")
	} else {
		a.VaultServer = strings.TrimSuffix(a.VaultServer, "/")
	}

	//
	// All the vault things rae setup, time to initalize things around
	// the client; really this just needs to be the CAPath
	a.initializeVaultHTTPClient()

	if err := a.appRole_login(); err != nil {
		return err
	}

	// deal with doubles that aren't supposed to exist
	return nil
}

// Build a usable appauthal structure given a previously initialized struct
// and a current file
func (a *AppAuthVaultMethod) BuildAppAuthAL(inmap interface{}) (goappauthal.AppAuthAuthEntry, error) {
	var rv AppAuthVaultAuthEntry
	rv.imp = make(map[string]string)
	rv.xlate = make(map[string]string)

	rv.method = a

	entry := inmap.(map[string]interface{})

	if entry["Method"].(string) != "vault" {
		return &rv, fmt.Errorf("Not a vault Method")
	}

	if i, ok := entry["import"]; ok {
		mapping := i.(map[string]interface{})
		for key, val := range mapping {
			p := val.(string)
			rv.imp[key] = p
		}
	}

	if i, ok := entry["map"]; ok {
		mapping := i.(map[string]interface{})
		for key, val := range mapping {
			p := val.(string)
			rv.xlate[key] = p
		}
	}

	if val, ok := entry["VaultPath"].(string); !ok {
		return &rv, fmt.Errorf("Mandary VaultPath not set")
	} else {
		rv.path = val
	}

	return &rv, nil
}

// / XXX probably need to have error here.  _sigh_
func (a *AppAuthVaultAuthEntry) BuildAuthenticateMap() map[string]string {
	rv := make(map[string]string)

	if a.haveCache {
		return a.cache
	}

	metadata, e := a.method.VaultReadRaw(a.path)
	if e != nil {
		return rv
	}

	vaultentry, e := a.method.ExtractVaultKV(metadata)
	if e != nil {
		return rv
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
	a.method.RevokeMyToken()

	a.haveCache = true
	a.cache = rv
	return a.cache
}

func (a *AppAuthVaultMethod) BuildCacheKey(rawentry goappauthal.AppAuthAuthEntry) string {
	entry := rawentry.(*AppAuthVaultAuthEntry)

	// This happens when the role id is pulled from a file.
	var roleid string
	if a.VaultRoleId != "" {
		roleid = a.VaultRoleId
	} else if a.token != "" {
		h := sha1.New()
		h.Write([]byte(a.token))
		roleid = hex.EncodeToString(h.Sum(nil))
	} else {
		roleid = ""
	}

	roleid = a.VaultRoleId

	// set to server or "" if no server is set
	server := a.VaultServer

	key := fmt.Sprintf("%s@%s/%s", server, roleid, entry.path)

	re := regexp.MustCompile("[/:]")
	return string(re.ReplaceAll([]byte(key), []byte("_")))
}

func (a *AppAuthVaultAuthEntry) GetExpiration() time.Time {
	return a.expiration
}

/*
sub _process_arguments($$) {
	my $self    = shift;
	my $appauth = shift;

	#
	# if VaultTokenPath is set, then the Role/Secrets are optional and it
	# is assumed that something external maintains this file.
	#
	# If it's not set, the minimum required to enable approle login is
	# required.
	#

	my $hasrole;
	my $hassecret;
	my $hastoken;

	if ( $appauth->{VaultTokenPath} ) {
		$self->{VaultTokenPath} = $appauth->{VaultTokenPath};
		$hastoken = 1;
	}

	if (   exists( $appauth->{VaultSecretId} )
		|| exists( $appauth->{VaultSecretIdPath} ) )
	{
		$hassecret = 1;
	}

	if (   exists( $appauth->{VaultRoleId} )
		|| exists( $appauth->{VaultRoleIdPath} ) )
	{
		$hasrole = 1;
	}

	if ($hastoken) {
		if ( ( $hassecret && !$hasrole ) || ( $hasrole && !$hassecret ) ) {
			$errstr =
			  "Either both Secret and Role information or neither must be passed when using tokens";
			return undef;
		}
	} elsif ( !$hassecret && !$hasrole ) {
		$errstr = "Token file must exist when secret/role data is not provided";
		return undef;
	}

	#
	# Either VaultSecretIdPath or VaultSecretId must be set.  Both may
	# not be set.  In the path case, the file is assumed to contain just
	# the role id similar to VaultSecretIdPath
	#
	if (   exists( $appauth->{VaultSecretId} )
		&& exists( $appauth->{VaultSecretIdPath} ) )
	{
		$errstr = "Both VaultSecretIdPath and VaultSecretId are set.";
		return undef;
	} elsif ( exists( $appauth->{VaultSecretIdPath} ) ) {
		if ( ( my $fh = new FileHandle( $appauth->{VaultSecretIdPath} ) ) ) {
			while ( my $l = $fh->getline() ) {
				chomp($l);
				$l =~ s/#.*$//;
				next if ( $l =~ /^\s*$/ );
				$self->{VaultSecretId} = $l;
				last;
			}
			$fh->close;
		} else {
			$errstr = sprintf "Unable to read Vault Secret Id from %s: %s",
			  $appauth->{VaultSecretIdPath},
			  $!;
			return undef;
		}
	} elsif ( exists( $appauth->{VaultSecretId} ) ) {
		$self->{VaultSecretId} = $appauth->{VaultSecretId};
	} elsif ( !$hastoken ) {
		$errstr = "Neither VaultSecretIdPath nor VaultSecetId are set.";
		return undef;
	}
	#
	# Either VaultRoleIdPath or VaultRoleId need to be set.  Both can not be
	# set.  In the path case, the file is assumed to contain just the role
	# id similar to VaultSecretIdPath
	#
	if (   exists( $appauth->{VaultRoleId} )
		&& exists( $appauth->{VaultRoleIdPath} ) )
	{
		$errstr = "Both VaultRoleIdPath and VaultRoleId are set.";
		return undef;
	} elsif ( exists( $appauth->{VaultRoleIdPath} ) ) {
		if ( ( my $fh = new FileHandle( $appauth->{VaultRoleIdPath} ) ) ) {
			while ( my $l = $fh->getline() ) {
				chomp($l);
				$l =~ s/#.*$//;
				next if ( $l =~ /^\s*$/ );
				$self->{VaultRoleId} = $l;
				last;
			}
			$fh->close;
		} else {
			$errstr = sprintf "Unable to read Vault Role Id from %s: %s",
			  $appauth->{VaultRoleIdPath},
			  $!;
			return undef;
		}
	} elsif ( exists( $appauth->{VaultRoleId} ) ) {
		$self->{VaultRoleId} = $appauth->{VaultRoleId};
	} elsif ( !$hastoken ) {
		$errstr = "Neither VaultRoleIdPath nor VaultRoleId are set.";
		return undef;
	}

	# extra check in case the above failed.
	if ( !$hastoken && !( defined( $self->{VaultSecretId} ) ) ) {
		$errstr = "VaultSecretId could not be determined.";
		return undef;
	}

	# extra check in case the above failed.
	if ( !$hastoken && !( defined( $self->{VaultRoleId} ) ) ) {
		$errstr = "VaultRoleId could not be determined.";
		return undef;
	}

	if (   $hastoken
		&& !( defined( $self->{VaultRoleId} ) )
		&& !( defined( $self->{VaultSecretId} ) ) )
	{
		if ( !-r $self->{VaultTokenPath} ) {
			$errstr = sprintf "Token file required but does not exist: %s",
			  $self->{VaultTokenPath};
			return undef;
		}
	}

	my $capath = $ENV{'VAULT_CAPATH'} || $appauth->{CAPath};
	if ( $capath) {
		if ( -f $capath ) {
			$self->{sslargs}->{SSL_ca_file} = $capath;
		} elsif ( -d $capath ) {
			$self->{sslargs}->{SSL_ca_path} = $capath;
		} else {
			$errstr = sprintf "Invalid CAPath %s", $capath;
			return undef;
		}
	}

	$self->{_appauthal} = $appauth;
}


*/
