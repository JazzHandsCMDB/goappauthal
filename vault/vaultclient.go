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
	"strings"
	"time"
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
	if a.token == "" {
		tok, err := a.readTokenFile()
		if err == nil {
			if a.checkToken(tok) == true {
				return nil
			}
		}
	}

	body, e := a.fetchVaultURLwithToken("", "POST", "auth/approle/login", "role_id", a.VaultRoleId, "secret_id", a.VaultSecretId)
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
				a.token_lease_duration = int64(f)

			} else {
				continue
			}
		}
	}

	fmt.Println("looking for cliecnt token in ", auth)
	if tok, ok := auth["client_token"]; !ok {
		return fmt.Errorf("Response did not include a Client token")
	} else {
		fmt.Println("saving token")
		a.token = tok
	}

	a.maybeWriteTokenFile()

	if a.token_lease_duration == 0 {
		a.token_lease_duration = 86400
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

// This is used to deal with vault calls _before_ there is a stable token,
// before logging, but most things will use the previous call which uses the
// method's token
func (a *AppAuthVaultMethod) fetchVaultURLwithToken(token string, method string, path string, args ...string) (string, error) {
	if a.client == nil {
		return "", fmt.Errorf("Variable was not initialized")
	}
	fmt.Printf("fetching vault url: %s\n", path)

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
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}

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

func (a *AppAuthVaultMethod) fetchVaultURL(method string, path string, args ...string) (string, error) {
	if a.token == "" {
		if a.VaultSecretId != "" && a.VaultRoleId != "" {
			fmt.Println("trying login")
			if err := a.appRole_login(); err != nil {
				return "", err
			}
		}
	}

	return a.fetchVaultURLwithToken(a.token, method, path, args...)
}

// checks to see if the set token is valid.  returns false if not or on
// error
func (a *AppAuthVaultMethod) checkToken(token string) bool {
	type TokenData struct {
		LeaseDuration float64 `json:"token_lease_duration"`
	}
	type Response struct {
		Data TokenData `json:"data"`
	}

	if token == "" {
		return false
	}

	body, e := a.fetchVaultURLwithToken(token, "GET", "auth/token/lookup-self")
	if e != nil {
		return false
	}

	var resp Response
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		return false
	}

	// ttl from lookup-self seems to be number of second remaining.
	// XXX keep? a.token_lease_duration = int64(resp.Data.LeaseDuration)
	return true
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

// Delete metadata from Vault
// Ex.: you have 'kv/data/myfirstapp/foo name=foo pass=bar'
//
// --> use 'VaultDelete' method on 'kv/myfirstapp/foo'
//
//	in order to delete the secrets (name and pass in this example)
//
// --> Use 'VaultDeleteMetadata' method on 'kv/myfirstapp/foo'
//
//	in order to delete the 'foo' path.
func (a *AppAuthVaultMethod) VaultDelete(path string) error {
	_, e := a.fetchVaultURL("DELETE", path)
	return e
}

// deletes the path, not just the secret (see comment for delete).
func (a *AppAuthVaultMethod) VaultDeleteMetadata(path string) error {
	path = strings.Replace(path, "/data/", "/metadata/", 1)
	_, e := a.fetchVaultURL("DELETE", path)
	return e
}
