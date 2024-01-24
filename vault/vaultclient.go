package govault

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
	"strings"
)

func (a *AppAuthVaultMethod) processCAdir(path string, pool *x509.CertPool) error {
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		data, err := os.ReadFile(path + "/" + entry.Name())
		if err == nil {
			pool.AppendCertsFromPEM(data)
		}
	}

	return nil
}

func (a *AppAuthVaultMethod) initializeVaultHTTPClient() error {

	// move to init  XXX
	caCertPool := x509.NewCertPool()
	if a.CAPath != "" {
		if info, err := os.Stat(a.CAPath); err != nil {
			return err
		} else if info.IsDir() {
			a.processCAdir(a.CAPath, caCertPool)
		} else {
			if caCert, err := os.ReadFile(a.CAPath); err != nil {
				return err
			} else {
				caCertPool.AppendCertsFromPEM(caCert)
			}
		}
	} else {
		if c, err := x509.SystemCertPool(); err != nil {
			return err
		} else {
			caCertPool = c
		}
	}

	a.client = &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: caCertPool}}}

	return nil
}

// login using an approle, but use a token if the tokenpath is set and it
// exists.  stash the token in said file if it's a different one.
func (a *AppAuthVaultMethod) appRole_login() error {
	// XXX cache check goes here

	body, e := a.fetchVaultURL("POST", "auth/approle/login", "role_id", a.VaultRoleId, "secret_id", a.VaultSecretId)
	if e != nil {
		return e
	}

	/*
	 * The response is a string:interface{} map, with a bunch of keys.
	 * The interesting one here is "data" (the rest are ignored, although
	 * perhaps lease stuff should not be.
	 *
	 * Within that are two more fields, data and metadata, data is the k/v
	 * to pass back to the client, metadata is all the exigent data about it;
	 * other language versions of this libraryt have an argument for metadata
	 * or not; perhaps this should too
	 *
	 * The code below processes the outer 'data", then the inner 'data"
	 */

	mymap := make(map[string]interface{})
	if err := json.Unmarshal([]byte(body), &mymap); err != nil {
		return err
	}

	auth := make(map[string]string)
	if authraw, ok := mymap["auth"]; !ok {
		return fmt.Errorf("Response did not have auth section")
	} else {
		authcook := authraw.(map[string]interface{})
		for key, val := range authcook {
			if key == "client_token" {
				v := val.(string)
				auth[key] = v
			} else if key == "lease_duration" {
				f := val.(float64)
				a.lease_duration = int64(f)

			} else {
				continue
			}
		}
	}

	if tok, ok := auth["client_token"]; !ok {
		return fmt.Errorf("Response did not include a Client token")
	} else {
		a.token = tok
	}

	if a.lease_duration == 0 {
		a.lease_duration = 86400
	}
	return nil
}

/*
 * revoke token obtained by all this, if in fact, it was.
 */
func (a *AppAuthVaultMethod) RevokeMyToken() error {
	_, e := a.fetchVaultURL("POST", "auth/token/revoke-self")
	if e != nil {
		return e
	}

	a.token = ""
	return nil
}

// XXX context?
func (a *AppAuthVaultMethod) fetchVaultURL(method string, path string, args ...string) (string, error) {
	if a.client == nil {
		return "", fmt.Errorf("Variable was not initialized")
	}

	if len(args)%2 != 0 {
		return "", fmt.Errorf("Uneven number of arugments")
	}

	url := fmt.Sprintf("%s/v1/%s", a.VaultServer, path)

	body := make(map[string]string)
	for i := 0; i < len(args); i += 2 {
		body[args[i]] = args[i+1]
	}

	var bodyjson []byte
	if len(body) > 0 {
		b, err := json.Marshal(body)
		if err != nil {
			return "", err
		}
		bodyjson = b
	}

	// begin making the http request

	var req *http.Request
	if r, err := http.NewRequestWithContext(context.Background(),
		method, url, bytes.NewBuffer(bodyjson)); err != nil {
		return "", err
	} else {
		req = r
	}

	req.Header.Set("User-Agent", "golangvaultXXX/0.50")
	req.Header.Set("X-Vault-Token", a.token)

	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	}

	res, err := a.client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Failed to Retrieve: %s", res.Status)
	}

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}
	bodyString := string(bodyBytes)
	return bodyString, nil
}

// XXX All this should be rethunk and possibly returning a type
func (a *AppAuthVaultMethod) VaultReadRaw(path string) (map[string]interface{}, error) {
	rawmap := make(map[string]interface{})
	body, e := a.fetchVaultURL("GET", path)
	if e != nil {
		return rawmap, e
	}

	if err := json.Unmarshal([]byte(body), &rawmap); err != nil {
		return rawmap, err
	}

	return rawmap, nil
}

func (a *AppAuthVaultMethod) ExtractVaultKV(rawmap map[string]interface{}) (map[string]string, error) {
	mymap := make(map[string]string)

	// interesting data is the "data" map
	if outerdata, ok := rawmap["data"]; !ok {
		return mymap, fmt.Errorf("No expected outer data field")
	} else {
		outermap := outerdata.(map[string]interface{})
		for outkey, outvalraw := range outermap {
			if outkey == "data" {
				outval := outvalraw.(map[string]interface{})
				for key, val := range outval {
					v := val.(string)
					mymap[key] = v
				}
				return mymap, nil
			}
		}
		return mymap, fmt.Errorf("No expected inner data field")
	}

	return mymap, fmt.Errorf("Reached end of ExtractVaultKV")
}

func (a *AppAuthVaultMethod) VaultRead(path string) (map[string]string, error) {
	rawmap := make(map[string]interface{})
	errmap := make(map[string]string)

	if r, err := a.VaultReadRaw(path); err != nil {
		return errmap, err
	} else {
		rawmap = r
	}

	mymap, e := a.ExtractVaultKV(rawmap)
	if e != nil {
		return errmap, e
	}

	return mymap, nil
}

func (a *AppAuthVaultMethod) VaultWriteMap(path string, inMap map[string]string) error {
	var args []string
	for k, v := range inMap {
		args = append(args, k, v)
	}

	_, e := a.fetchVaultURL("POST", path, args...)
	return e
}

func (a *AppAuthVaultMethod) VaultWrite(path string, args ...string) error {
	_, e := a.fetchVaultURL("POST", path, args...)
	return e
}

func (a *AppAuthVaultMethod) List(path string) ([]string, error) {
	var rv_err []string

	type VData struct {
		Keys []string `json:"keys"`
	}
		
	type VList struct {
		Data VData `json:"data"`
	}

	path = strings.Replace(path, "/data/", "/metadata/", 1)
	body, e := a.fetchVaultURL("LIST", path)
	if e != nil {
		return rv_err, e
	}

	var answer VList
	if err := json.Unmarshal([]byte(body), &answer); err != nil {
		return rv_err, nil
	}

	return answer.Data.Keys, nil
}

//
// Delete metadata from Vault
// Ex.: you have 'kv/data/myfirstapp/foo name=foo pass=bar'
//
// --> use 'VaultDelete' method on 'kv/myfirstapp/foo'
//     in order to delete the secrets (name and pass in this example)
// --> Use 'VaultDeleteMetadata' method on 'kv/myfirstapp/foo'
//     in order to delete the 'foo' path.
//
func (a *AppAuthVaultMethod) VaultDelete(path string) error {
	_, e := a.fetchVaultURL("DELETE", path)
	return e
}

// deletes the path, not just the secret (see comment for delete).
func (a *AppAuthVaultMethod) VaultDeleteMetadata(path string) error {
	path = strings.Replace(path, "/data/", "/metadata/", 1)

	url := fmt.Sprintf("%s/v1/%s", a.VaultServer, path)
	_, e := a.fetchVaultURL("DELETE", path)
	return e
}

/*
#
# takes $appauthal argument that's a hash of all the things required to
# talk to vault.
#
sub new {
	my $proto = shift;
	my $class = ref($proto) || $proto;
	my $self  = $class->SUPER::new(@_);

	my $opt = &_options(@_);
	if ( my $appauth = $opt->{appauthal} ) {
		_process_arguments( $self, $appauth ) || return undef;

		#
		# This is required for appauthal mode but not useful in non-appauthal
		# form.
		#
		foreach my $thing (qw(VaultPath )) {
			if ( ( !exists( $appauth->{$thing} ) )
				|| !defined( $appauth->{$thing} ) )
			{
				$errstr = "Mandatory Vault Parameter $thing not specified";
				return undef;
			}
		}
	} else {
		_process_arguments( $self, $opt ) || return undef;

		#
		# Not valid for non-appauthal form
		#
		foreach my $thing (qw(VaultPath )) {
			if ( ( exists( $appauth->{$thing} ) )
				|| defined( $appauth->{$thing} ) )
			{
				$errstr = "$thing is not permitted in non-appauthal form";
				return undef;
			}
		}

		# now go make sure we are ready to do vault ops
		$self->approle_login() || return undef;
	}

	return bless $self, $class;
}

sub _readtoken($) {
	my $self = shift @_;

	return undef if ( !exists( $self->{_appauthal}->{VaultTokenPath} ) );
	return undef if ( !defined( $self->{_appauthal}->{VaultTokenPath} ) );
	return undef if ( !-r $self->{_appauthal}->{VaultTokenPath} );

	my $fn = $self->{_appauthal}->{VaultTokenPath};

	#
	# what to do if $token is already set?
	#
	my $token;
	if ( ( my $fh = new FileHandle($fn) ) ) {
		$token = $fh->getline();
		$fh->close;
		chomp($token);
	}

	$token;

}

#
# return 0 if the approle dance needs to happen
# return 1 if we have a valid token already.
#
sub _check_and_test_token_cache($) {
	my $self = shift @_;

	if ( !$self->{_token} ) {
		my $token = $self->_readtoken();

		delete( $self->{_token} );
		delete( $self->{token_lease_duration} );

		if ($token) {
			my $url = sprintf "%s/v1/auth/token/lookup-self",
			  $self->{_appauthal}->{VaultServer};

			my $resp = $self->_fetchurl(
				method => 'GET',
				url    => $url,
				token  => $token,
			);

			if ( $resp && $resp->{data} ) {
				$self->{_token}               = $token;
				$self->{token_lease_duration} = $resp->{data}->{ttl};
			}
		}
	} else {
		return (0);
	}

	if ( !defined( $self->{token_lease_duration} ) ) {
		return 0;
	}

	# does not expire.
	if ( $self->{token_lease_duration} == 0 ) {
		return 1;
	}

	# ttl from lookup-self seems to be number of second remaining.
	if ( $self->{token_lease_duration} > $ttl_refresh_seconds ) {
		return 1;
	}

	return 0;
}

#
# save the token if it's possible to save it.
#
# returns undef on fail, the token on success
#
sub _save_token($$) {
	my $self = shift @_;
	my $auth = shift @_;

	my $token = $auth->{client_token};

	return undef if ( !exists( $self->{_appauthal}->{VaultTokenPath} ) );
	return undef if ( !defined( $self->{_appauthal}->{VaultTokenPath} ) );
	my $tokenpath = $self->{_appauthal}->{VaultTokenPath};

	my $d     = dirname($tokenpath);
	my $tmpfn = $tokenpath . "_tmp.$$";

	if ( !-w $tokenpath ) {
		return undef if ( !-w $d );
	}

	my $curtok = $self->_readtoken( $self->{_appauthal}->{VaultTokenPath} );
	return $token if ( $curtok && $curtok eq $token );

	if ( !-w $d ) {

		# gross but Vv
		$tmpfn = $tokenpath;
	}

	if ( my $fh = new FileHandle( ">" . $tmpfn ) ) {
		$fh->printf( "%s\n", $token );
		$fh->close;

		if ( $tmpfn ne $tokenpath ) {
			my $oldfn = $tokenpath . "_old";
			unlink($oldfn);
			rename( $tokenpath, $oldfn );
			if ( !rename( $tmpfn, $tokenpath ) ) {
				rename( $oldfn, $tokenpath );
			} else {
				unlink($oldfn);
			}
		}
	}

	$token;
}

#
# arguably needs to take the path asn an argument and become "read" or "get"
#
sub _get_vault_path($$) {
	my $self = shift @_;
	my $path = shift @_;

	my $opt = &_options(@_);

	my $url = sprintf "%s/v1/%s", $self->{_appauthal}->{VaultServer}, $path;

	my $resp = $self->_fetchurl( url => $url, );

	if ( !$resp ) {
		$errstr = "did not receive credentials from vault server";
		return undef;

	}

	if ( !$resp->{data} ) {
		$errstr = "No dbauth data returned in vault request to $url";
		return undef;
	}
	#
	# dynamic credentials are different.  It's possible the smarts here
	# should be moved to the caller.

	#
	my $dbauth;
	if ( $resp->{data}->{data} ) {
		$dbauth = $resp->{data}->{data};
	} else {
		$dbauth = $resp->{data};
	}

	if ( $resp->{lease_duration} ) {
		$dbauth->{'lease_duration'} = $resp->{lease_duration};
	}
	$dbauth;
}

#
# this does the login and fetches the key.
#
sub fetch_and_merge_dbauth {
	my $self = shift @_;
	my $auth = shift @_;

	my $vaultpath = $self->{_appauthal}->{VaultPath};
	if ( !$vaultpath ) {
		$errstr = "Class was not instantiated for appauthal usage";
		return undef;
	}

	$self->approle_login                           || return undef;
	my $vault = $self->_get_vault_path($vaultpath) || return undef;

	my $rv = {};
	if ( exists( $auth->{import} ) ) {
		foreach my $key ( keys %{ $auth->{import} } ) {
			$rv->{$key} = $auth->{import}->{$key};
		}
	}
	if ( exists( $auth->{map} ) ) {
		foreach my $key ( keys %{ $auth->{map} } ) {
			my $vkey = $auth->{map}->{$key};
			$rv->{$key} = $vault->{$vkey};
		}
	}

	if ( exists( $vault->{'lease_duration'} ) ) {
		$rv->{'__Expiration'} = $vault->{'lease_duration'};
	}

	$rv;
}

*/
