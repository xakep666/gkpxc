KeepassXC RPC client for Go
========

[![Go Reference](https://pkg.go.dev/badge/github.com/xakep666/gkpxc.svg)](https://pkg.go.dev/github.com/xakep666/gkpxc)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Test](https://github.com/xakep666/gkpxc/actions/workflows/testing.yml/badge.svg)](https://github.com/xakep666/gkpxc/actions/workflows/testing.yml)

This library allows to interact with [KeepassXC Browser Integration](https://keepassxc.org/docs/KeePassXC_GettingStarted.html#_setup_browser_integration) server.
It's protocol not documented well but can be found in [source code](https://github.com/keepassxreboot/keepassxc/blob/2.7.1/src/browser/BrowserAction.cpp#L34).
This repository also contains additional "adapter" utilities for storing credentials in KeepassXC database.

# Additional utilities
* [Docker Credential Helper](./dockercred/README.md)

# Usage
Protocol uses "request-response" model but also contains some asynchronous notifications.
Typical workflow:
0. Create client
1. Request database hash using `Client.GetDatabaseHash`.
2. Lookup association credentials by received hash and use it `Client.SetAssociationCredentials`.
3. Request a new association if such credentials was not found on step 2 using `Client.Associate`.
        Then get them using `Client.AssociationCredentials` and store in safe place.
4. Optionally subscribe to asynchronous events.
5. Make requests.
6. Close client.

## Example

```go
package main

import (
	"context"
	"fmt"

	"github.com/xakep666/gkpxc"
)

func main() {
	client, err := gkpxc.NewClient(context.Background(), gkpxc.WithLockChangeHandler(func(locked bool) {
		fmt.Printf("lock changed: %t\n", locked)
	}))
	if err != nil {
		panic(err)
    }
	
	defer client.Close()

	dbHash, err := client.GetDatabaseHash(context.Background(), false)
	if err != nil {
		panic(err)
	}
	
	fmt.Printf("KeepassXC version: %s, Database hash: %s\n", dbHash.Version, dbHash.Hash)
	
	err = client.Associate(context.Background())
	if err != nil {
		panic(err)
    }
	
	associationCreds := client.AssociationCredentials()
	// store them somewhere
	fmt.Printf("Association ID: %s, Association private key: %v\n", associationCreds.ID, associationCreds.PrivateKey)
	
	groups, err := client.GetDatabaseGroups(context.Background())
	if err != nil {
		panic(err)
    }
	
	for _, group := range groups.Groups.Groups {
		fmt.Printf("Group UUID: %s, name: %s\n", group.UUID, group.Name)
    }
}
```

# Testing

This library contains two kind of tests: unit and integration.

Unit-tests runs with just `go test`.

Integration tests adds some requirements:
* KeepassXC at least 2.7.0 installed on your system
* KeepassXC is not running
* Requirements for additional utilities (see in corresponding README's).

To specify custom KeepassXC executable location use `KEEPASSXC_EXECUTABLE` environment variable (i.e. [testing.yml](.github/workflows/testing.yml)).

To run integration tests use `go test -tags integration ./...`.

Note that some tests contain long sleeps used to wait for KeepassXC startup.
