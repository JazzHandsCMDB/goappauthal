/*
godbi is an appauthal method for logging in into databases

Import github.com/jazzhandscmdb/goappauthal/db and the underlying database
module, which can be imported anonymously.  At this point it's only been
tested with github.com/jackc/pgx/v5/stdlib, but that should be addresed.

NOTE: The session user magic used in other languages DOES NOT WORK.  This is
because of how golang splits opening a connection and connection pools.  This
requires more attention, but in the meantime, calling apps need to set and
reset the jazzhands.appuser if they want to use it.

To switch the underlying driver, something like this:

	if err := godbi.SetDatabaseDriver("postgresql", "pgx"); err != nil {
	        log.Fatal(err)
	}

pgx, however, is the default.

To connect:

	db, e := godbi.Connect(app)
	if e != nil {
	        log.Fatal(e)
	}

This is the golang implementation of the Application Authorization Layer for
talking to databases.   Given application details, the library figures out
connection details, connects and returns a database handle for talking to said
database.  This allows connection information to be completely outside the
code, stored in a standardized fashion.

There is support for various login methods, including using Hashicorp Vault
to store the actual crednetials, which is handled by the govault
module.  Note that the it is still necessary for the calling application
to ensure the correct underlying database module is included, and in the
case of things like hashicorp vault, that is also included.

DBI/databse configuration happens under the top level "database" stanza.
Ultimately the DBType must be set, and based on that typically also
Username, Password, DBName, DBHost and DBPort although if the underlying
library has defaults, they can be left out.  The Method argument can be
password, which just does basic username and password auth or Vault, which
uses Hashicorp Vault to determine credentials and synthesize a dbauth entry
that gets parsed by this library.  JazzHands::Vault contains the information
on how this works.

An example of a minimal configuration for a database is this:

	{
	      "database": {
	              "DBType": "postgresql",
	              "Method": "password",
	              "DBHost": "jazzhands-db.example.com",
	              "DBName": "jazzhands",
	              "Username": "app_stab",
	              "Password": "thisisabadpassword"
	      }
	}

Values are case sensitive.  It is possible to set the value to a an array of
entries, in which case they are tried serially until one works.

The global configuration file (defaults to /etc/jazzhands/appauth.json) can
be used to define system wide defaults.  It is optional.

The file format for dbauth files themselves is documented in
goappautahl and the Hashicorp vault specifics can be found in
govault
*/
package godbi

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
	"database/sql"
	"fmt"
	"github.com/jazzhandscmdb/goappauthal"
	"log"
	"os"
	"os/user"
	"reflect"
	"strings"
)

type Database struct {
	Method   string
	DBType   string
	DBHost   string
	DBName   string
	Username string
	Password string

	// These are all for Method Vault
	VaultPath string
	Import    map[string]string
	TokenMap  map[string]string `json:"map"`
}

// taken from DBI.pm
// XXX - _DBD becomes driver, figure out how to change, and include from a
// parent class, _not_ here.
var dbAALMap = map[string]map[string]string{
	"postgresql": {
		"_Driver":  "pgx",
		"DBName":   "dbname",
		"DBHost":   "host",
		"DBPort":   "port",
		"Options":  "options",
		"Service":  "service",
		"Username": "user",
		"Password": "password",
		"SSLMode":  "sslmode",
	},
	/*
		 none of these are tested yet
			"mysql": {
				"_Driver":           "mysql",
				"DBName":         "database",
				"DBHost":         "host",
				"DBPort":         "port",
				"Compress":       "mysql_compression",
				"ConnectTimeout": "mysql_connect_timeout",
				"SSLMode":        "mysql_ssl",
			},
			"odbc": {
				"_DBD":     "ODBC",
				"DSN":      "dsn",
				"DBName":   "database",
				"DBDriver": "driver",
				"DBHost":   "server",
				"DBPort":   "port",
				"SSLMode":  "sslmode",
			},
			"tds": {
				"_DBD": "Sybase",
			},
			"sqlite": {
				"_DBD":      "SQLite",
				"DBName":    "dbname",
				"_fileonly": "yes",
			},
	*/
}

func SetDatabaseDriver(dbtype string, driver string) error {
	if _, ok := dbAALMap[dbtype]; !ok {
		return fmt.Errorf("Unknown DBType: %s", dbtype)
	}
	dbAALMap[dbtype]["_Driver"] = driver
	return nil
}

func buildConnectionString(inmap map[string]string) (string, string, error) {
	if _, ok := dbAALMap[inmap["DBType"]]; !ok {
		return "", "", fmt.Errorf("Unsupported DBType", inmap["DBType"])
	}

	thisdb := dbAALMap[inmap["DBType"]]

	var connstr []string
	for k, v := range inmap {
		if k == "DBType" {
			continue
		} else if finalkey, ok := thisdb[k]; ok {
			connstr = append(connstr, fmt.Sprintf("%s=%s", finalkey, v))
		}
	}

	return strings.Join(connstr, " "), thisdb["_Driver"], nil
}

func SetSessionUser(dbc *sql.DB, login string) error {
	if login == "" {
		if curuser, err := user.Current(); err == nil {
			login = curuser.Username
		}
	}
	// meh.  patches welcome.
	driver := dbc.Driver()
	driverName := reflect.TypeOf(driver).String()

	// use the db specific way to set this
	if driverName == "*stdlib.Driver" { // pgx
		blah := fmt.Sprintf("set jazzhands.appuser to '%s';", login)
		a, e := dbc.Exec(blah)
		fmt.Printf("%s: 1: %#v 2: %#v ;fin", blah, a, e)
		return nil
	} else if driverName == "*oracle.Driver" { // untested
		dbc.Exec(fmt.Sprintf("dbms_session.set_identifier ('%s')"), login)
		return nil
	} else {
		return fmt.Errorf("Unsupported Database Type")
	}
}

/*
 * This always returns an sql.Db (or nil) but it's any because of appauthal
 * abstration any to conform with dbauth abstraction.
 *
 * goappauthal will cache login when secrets managements systems are in the
 * loop and it does this somewhat transparently.
 */
func attemptConnect(appauth map[string]string, state any) (any, error) {
	connstr, driver, e := buildConnectionString(appauth)
	if e == nil {
		dbc, err := sql.Open(driver, connstr)
		if err == nil {
			SetSessionUser(dbc, "")
			return dbc, e
		} else {
			return nil, err
		}
	}
	return nil, e
}

func Connect(app string) (*sql.DB, error) {
	var parsedaalmap map[string]interface{}

	parsedaal, err := goappauthal.FindAndProcessAuth(app)
	if err != nil {
		return nil, err
	}

	parsedaalmap = parsedaal.(map[string]interface{})

	optmap := make(map[string]interface{})
	if o, e := parsedaalmap["options"]; e {
		optmap = o.(map[string]interface{})
	}
	for _, rawdb := range parsedaalmap["database"].([]interface{}) {
		db := rawdb.(map[string]interface{})
		dbc, err := goappauthal.DoCachedLogin(optmap, db, attemptConnect, nil)
		if err == nil {
			return dbc.(*sql.DB), err
		} else {
			return nil, err
		}
	}

	return nil, fmt.Errorf("Unable to login (likely no entries)")

}

func main() {
	app := os.Args[1]

	db, e := Connect(app)
	if e != nil {
		log.Fatal(e)
	}

	rows, err := db.Query("select count(*) as tally from device")
	if err != nil {
		log.Fatal(err)
	}
	for rows.Next() {
		var tally int
		err := rows.Scan(&tally)
		if err != nil {
			log.Fatal(err)
		}
		log.Println(tally)
	}
	err = rows.Err()
	if err != nil {
		log.Fatal(err)
	}
}
