package dockercred

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"

	"github.com/99designs/keyring"
	"github.com/docker/docker-credential-helpers/credentials"

	"github.com/xakep666/gkpxc"
)

type KeepassXCHelper struct {
	Keyring keyring.Keyring

	client *gkpxc.Client
}

func (h *KeepassXCHelper) Add(credentials *credentials.Credentials) error {
	if err := h.initialize(); err != nil {
		return err
	}

	ctx := context.Background()

	group, err := h.getOrCreateGroup()
	if err != nil {
		return err
	}

	var entryUUID string
	if existingLogins, err := h.client.GetLogins(ctx, gkpxc.GetLoginsRequest{URL: credentials.ServerURL}); err == nil {
		for _, entry := range existingLogins.Entries {
			if entry.Login == credentials.Username {
				entryUUID = entry.UUID
			}
		}
	}

	return h.client.SetLogin(ctx, gkpxc.SetLoginRequest{
		URL:       addHTTPS(credentials.ServerURL),
		Login:     credentials.Username,
		Password:  credentials.Secret,
		Group:     group.Name,
		GroupUUID: group.UUID,
		UUID:      entryUUID,
	})
}

func (h *KeepassXCHelper) Delete(serverURL string) error {
	if err := h.initialize(); err != nil {
		return err
	}

	var keepassError *gkpxc.ErrorResponse

	logins, err := h.client.GetLogins(context.Background(), gkpxc.GetLoginsRequest{URL: serverURL})
	switch {
	case errors.Is(err, nil):
		return h.client.DeleteEntry(context.Background(), gkpxc.DeleteEntryRequest{UUID: logins.Entries[0].UUID})
	case errors.As(err, &keepassError) && keepassError.Code == 15:
		return credentials.NewErrCredentialsNotFound()
	default:
		return err
	}
}

func (h *KeepassXCHelper) Get(serverURL string) (string, string, error) {
	if err := h.initialize(); err != nil {
		return "", "", err
	}

	var keepassError *gkpxc.ErrorResponse

	logins, err := h.client.GetLogins(context.Background(), gkpxc.GetLoginsRequest{URL: addHTTPS(serverURL)})
	switch {
	case errors.Is(err, nil):
		return logins.Entries[0].Login, logins.Entries[0].Password, nil
	case errors.As(err, &keepassError) && keepassError.Code == 15:
		return "", "", credentials.NewErrCredentialsNotFound()
	default:
		return "", "", err
	}
}

func (h *KeepassXCHelper) List() (map[string]string, error) {
	// keepass doesn't allow credentials listing
	return nil, nil
}

func (h *KeepassXCHelper) initialize() error {
	if h.client != nil {
		return nil
	}

	ctx := context.Background()

	client, err := gkpxc.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("keepassxc connect failed: %w", err)
	}

	dbHash, err := client.GetDatabaseHash(ctx, true)
	if err != nil {
		return fmt.Errorf("get database hash failed: %w", err)
	}

	secret, err := h.Keyring.Get(dbHash.Hash)
	switch {
	case errors.Is(err, nil):
		var cred gkpxc.AssociationCredentials
		if err = json.Unmarshal(secret.Data, &cred); err == nil {
			client.SetAssociationCredentials(&cred)
			break
		}

		fallthrough
	case errors.Is(err, keyring.ErrKeyNotFound):
		if err = client.Associate(ctx); err != nil {
			return fmt.Errorf("association failed: %w", err)
		}

		serialized, err := json.Marshal(client.AssociationCredentials())
		if err != nil {
			return fmt.Errorf("serialize association credentials failed: %w", err)
		}

		if err = h.Keyring.Set(keyring.Item{Key: dbHash.Hash, Data: serialized}); err != nil {
			return fmt.Errorf("store association credentials failed: %w", err)
		}
	default:
		return fmt.Errorf("association key get failed: %w", err)
	}

	h.client = client

	return nil
}

func (h *KeepassXCHelper) getOrCreateGroup() (gkpxc.DatabaseGroup, error) {
	ctx := context.Background()

	groups, err := h.client.GetDatabaseGroups(ctx)
	if err != nil {
		return gkpxc.DatabaseGroup{}, fmt.Errorf("get database groups failed: %w", err)
	}

	for _, group := range groups.Groups.Groups {
		if group.Name == credentials.CredsLabel {
			return group, nil
		}
	}

	group, err := h.client.CreateNewGroup(ctx, gkpxc.CreateNewGroupRequest{Name: credentials.CredsLabel})
	if err != nil {
		return gkpxc.DatabaseGroup{}, fmt.Errorf("create group failed: %w", err)
	}

	return gkpxc.DatabaseGroup{
		Name: group.Name,
		UUID: group.UUID,
	}, nil
}

func addHTTPS(strURL string) string {
	// to correctly name and query records we should add scheme
	if u, err := url.Parse(strURL); err == nil && u.Scheme == "" {
		u.Scheme = "https"
		strURL = u.String()
	}
	return strURL
}
