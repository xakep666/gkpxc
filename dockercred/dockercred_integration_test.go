//go:build integration

package dockercred_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/99designs/keyring"
	"github.com/docker/docker-credential-helpers/credentials"

	"github.com/xakep666/gkpxc"
	"github.com/xakep666/gkpxc/dockercred"
	"github.com/xakep666/gkpxc/internal/keerun"
)

func init() {
	keyring.Debug = true
}

func TestKeepassXCHelper_Integration(t *testing.T) {
	k, err := keerun.NewKeeRun(t)
	if err != nil {
		t.Fatal(err)
	}

	if err = k.Start(); err != nil {
		t.Fatal("Start keepass", err)
	}

	t.Cleanup(func() { k.KillWait() })

	time.Sleep(30 * time.Second) // time to start

	var creds gkpxc.AssociationCredentials
	if err = keerun.DecodeAssociationCreds(&creds); err != nil {
		t.Fatal("Get credentials", err)
	}

	jsonCreds, err := json.Marshal(creds)
	if err != nil {
		t.Fatal("Serialize credentials", err)
	}

	kr, err := dockercred.SetupKeyring("dockercred-test")
	if err != nil {
		t.Fatal("Setup keyring", err)
	}

	err = kr.Set(keyring.Item{Key: creds.Hash, Data: jsonCreds})
	if err != nil {
		t.Fatal("Write credentials", err)
	}

	t.Cleanup(func() { kr.Remove(creds.Hash) })

	helper := dockercred.KeepassXCHelper{Keyring: kr}

	t.Run("use existing", func(t *testing.T) {
		user, pass, err := helper.Get("https://site1.com")
		if err != nil {
			t.Fatal("Get login", err)
		}

		if user != "user1" || pass != "pass1" {
			t.Fatalf("Expected user1:pass1, got %s:%s", user, pass)
		}
	})

	t.Run("login and use", func(t *testing.T) {
		err := helper.Add(&credentials.Credentials{
			ServerURL: "https://test.registry",
			Username:  "registry_user",
			Secret:    "registry_secret",
		})
		if err != nil {
			t.Fatal("Add record", err)
		}

		user, pass, err := helper.Get("https://test.registry")
		if err != nil {
			t.Fatal("Get login", err)
		}

		if user != "registry_user" || pass != "registry_secret" {
			t.Fatalf("Expected registry_user:registry_secret, got %s:%s", user, pass)
		}
	})

	t.Run("login and use without protocol", func(t *testing.T) {
		err := helper.Add(&credentials.Credentials{
			ServerURL: "test.registry1",
			Username:  "registry1_user",
			Secret:    "registry1_secret",
		})
		if err != nil {
			t.Fatal("Add record", err)
		}

		user, pass, err := helper.Get("test.registry1")
		if err != nil {
			t.Fatal("Get login", err)
		}

		if user != "registry1_user" || pass != "registry1_secret" {
			t.Fatalf("Expected registry1_user:registry1_secret, got %s:%s", user, pass)
		}
	})

	t.Run("delete", func(t *testing.T) {
		t.Skip("TODO: wait for new release")

		err := helper.Delete("https://site1.com")
		if err != nil {
			t.Fatal("Delete", err)
		}

		_, _, err = helper.Get("https://site1.com")
		if !credentials.IsErrCredentialsNotFound(err) {
			t.Fatalf("Unexpected error %s, expected ErrCredentialsNotFound", err)
		}
	})
}
