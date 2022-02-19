//go:build integration

package gkpxc_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/xakep666/gkpxc"
	"github.com/xakep666/gkpxc/internal/keerun"
)

func TestClient_Integration(t *testing.T) {
	k, err := keerun.NewKeeRun()
	if err != nil {
		t.Fatal(err)
	}

	if err = k.Start(); err != nil {
		t.Fatal("Start keepass", err)
	}

	t.Cleanup(func() { k.KillWait() })

	time.Sleep(1 * time.Second) // time to start

	var creds gkpxc.AssociationCredentials
	if err = keerun.DecodeAssociationCreds(&creds); err != nil {
		t.Fatal("Get creds", err)
	}

	client, err := gkpxc.NewClient(context.Background())
	if err != nil {
		t.Fatal("Create client", err)
	}

	// ensure hash equal
	dbHash, err := client.GetDatabaseHash(context.Background(), false)
	if err != nil {
		t.Fatal("Get hash", err)
	}

	if dbHash.Hash != creds.Hash {
		t.Fatalf("DB hash %s not equal credential hash %s", dbHash.Hash, creds.Hash)
	}

	client.SetAssociationCredentials(&creds)

	t.Run("GetDatabaseGroups", func(t *testing.T) {
		groups, err := client.GetDatabaseGroups(context.Background())
		if err != nil {
			t.Fatal("Get groups", err)
		}

		if groups.Groups.Groups[0].Name != "root" ||
			groups.Groups.Groups[0].Children[0].Name != "group1" ||
			groups.Groups.Groups[0].Children[0].Children[0].Name != "group11" {
			t.Fatalf("Unexpected groups: %+v", groups)
		}
	})

	t.Run("CreateNewGroup", func(t *testing.T) {
		t.Skip("TODO: find way to press approval button")
	})

	t.Run("SetLogin", func(t *testing.T) {
		err := client.SetLogin(context.Background(), gkpxc.SetLoginRequest{
			URL:      "http://site2.com",
			Login:    "user2",
			Password: "pass2",
		})
		if err != nil {
			t.Fatal("Set login", err)
		}

		logins, err := client.GetLogins(context.Background(), gkpxc.GetLoginsRequest{URL: "http://site2.com"})
		if err != nil {
			t.Fatal("Get login", err)
		}

		if logins.Count != 1 ||
			logins.Entries[0].Name != "site2.com" ||
			logins.Entries[0].Login != "user2" ||
			logins.Entries[0].Password != "pass2" {
			t.Fatalf("Unexpected logins: %+v", logins)
		}
	})

	t.Run("GetLogins", func(t *testing.T) {
		logins, err := client.GetLogins(context.Background(), gkpxc.GetLoginsRequest{URL: "http://site1.com"})
		if err != nil {
			t.Fatal("Get login", err)
		}

		if logins.Count != 1 ||
			logins.Entries[0].Name != "rec1" ||
			logins.Entries[0].Login != "user1" ||
			logins.Entries[0].Password != "pass1" {
			t.Fatalf("Unexpected logins: %+v", logins)
		}
	})

	t.Run("DeleteEntry", func(t *testing.T) {
		t.Skip("TODO: wait for new release")
	})

	t.Run("GeneratePassword", func(t *testing.T) {
		t.Skip("TODO: find way to detect window show")
	})

	t.Run("GetTOTP", func(t *testing.T) {
		logins, err := client.GetLogins(context.Background(), gkpxc.GetLoginsRequest{URL: "http://totpsite.com"})
		if err != nil {
			t.Fatal("Get login", err)
		}

		if logins.Count != 1 {
			t.Fatalf("Unexpected logins: %+v", logins)
		}

		totp, err := client.GetTOTP(context.Background(), gkpxc.GetTOTPRequest{UUID: logins.Entries[0].UUID})
		if err != nil {
			t.Fatal("Get TOTP", err)
		}

		t.Log("TOTP", totp.TOTP)
	})

	t.Run("RequestAutoType", func(t *testing.T) {
		t.Skip("TODO: is it possible to check?")
	})
}

func TestClient_Client_locks_Integration(t *testing.T) {
	k, err := keerun.NewKeeRun()
	if err != nil {
		t.Fatal(err)
	}

	if err = k.Start(); err != nil {
		t.Fatal("Start keepass", err)
	}

	t.Cleanup(func() { k.KillWait() })

	time.Sleep(1 * time.Second) // time to start

	var creds gkpxc.AssociationCredentials
	if err = keerun.DecodeAssociationCreds(&creds); err != nil {
		t.Fatal("Get creds", err)
	}

	var (
		wg          sync.WaitGroup
		lockSignals []bool
	)

	wg.Add(1)
	client, err := gkpxc.NewClient(context.Background(), gkpxc.WithLockChangeHandler(func(locked bool) {
		lockSignals = append(lockSignals, locked)
		wg.Done()
	}))
	if err != nil {
		t.Fatal("Create client", err)
	}

	client.SetAssociationCredentials(&creds)

	if err = client.LockDatabase(context.Background()); err != nil {
		t.Fatal("Lock database", err)
	}

	wg.Wait()
	if len(lockSignals) != 1 || !lockSignals[0] {
		t.Fatalf("Unexpected lock signals: %+v", lockSignals)
	}

	var kpErr *gkpxc.ErrorResponse
	_, err = client.GetLogins(context.Background(), gkpxc.GetLoginsRequest{URL: "http://site1.com"})
	if !errors.As(err, &kpErr) {
		t.Fatal("Unexpected error", err)
	}

	if kpErr.Code != 1 {
		t.Fatalf("Unexpected error response: %+v", kpErr)
	}
}

func TestClient_External_locks_Integration(t *testing.T) {
	k, err := keerun.NewKeeRun()
	if err != nil {
		t.Fatal(err)
	}

	if err = k.Start(); err != nil {
		t.Fatal("Start keepass", err)
	}

	t.Cleanup(func() { k.KillWait() })

	time.Sleep(1 * time.Second) // time to start

	var creds gkpxc.AssociationCredentials
	if err = keerun.DecodeAssociationCreds(&creds); err != nil {
		t.Fatal("Get creds", err)
	}

	var (
		wg          sync.WaitGroup
		lockSignals []bool
	)

	wg.Add(1)
	client, err := gkpxc.NewClient(context.Background(), gkpxc.WithLockChangeHandler(func(locked bool) {
		lockSignals = append(lockSignals, locked)
		wg.Done()
	}))
	if err != nil {
		t.Fatal("Create client", err)
	}

	client.SetAssociationCredentials(&creds)

	if err = k.Lock(); err != nil {
		t.Fatal("Lock database", err)
	}

	wg.Wait()
	if len(lockSignals) != 1 || !lockSignals[0] {
		t.Fatalf("Unexpected lock signals: %+v", lockSignals)
	}

	var kpErr *gkpxc.ErrorResponse
	_, err = client.GetLogins(context.Background(), gkpxc.GetLoginsRequest{URL: "http://site1.com"})
	if !errors.As(err, &kpErr) {
		t.Fatal("Unexpected error", err)
	}

	if kpErr.Code != 1 {
		t.Fatalf("Unexpected error response: %+v", kpErr)
	}
}
