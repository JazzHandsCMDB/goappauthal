package godbi

import (
	"database/sql"
	"fmt"
	"github.com/jazzhandscmdb/goappauthal"
	"log"
	"os"
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
			return dbc, e
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
			// XXX user session stuff
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
