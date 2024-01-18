# goappauthal
Go implementation of the appauth libraries used by various JazzHands
utilities.

This is a golang implementation of the appauthal database connection functions.

It covers the most common cases but does not have complte feature parity
with the perl and python libraries.

It includes basic support for password and Hasicorp Vault access.

Things missing:
- kerberos support
- jazzhands.appuser/session user magic
- vault library does not suppose just creating and using a vault handle (yet)

These will all be addressed, but at the moment are not.

Typical use is to obtain a databse handle and it's something like this:

```
package main

import (
        "github.com/jazzhandscmdb/goappauthal/db"
        "github.com/jackc/pgx/v5/stdlib"
        "os"
        "log"
)

func main() {
        app := os.Args[1]


        db, e := godbi.Connect(app)
        if e != nil {
                log.Fatal(e)
        }
        defer db.Close()

        rows, err := db.Query("select count(*) as tally from thing")
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
```

NOTE that the underlying database library does need to be included
anonymously.

See the appauthal go dodbi go docs for more details.
