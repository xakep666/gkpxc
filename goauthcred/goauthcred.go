package goauthcred

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/99designs/keyring"
	"github.com/xakep666/gkpxc"
)

type ServeParams struct {
	Input            io.Reader
	Output           io.Writer
	Args             []string
	Keyring          keyring.Keyring
	TransformEntries func(entries []gkpxc.LoginEntry) ([]OutputEntry, error) // custom transform callback, optional
}

type OutputEntry struct {
	URLs    []string
	Headers http.Header
}

func Serve(ctx context.Context, params ServeParams) error {
	client, err := initClient(ctx, params.Keyring)
	if err != nil {
		return fmt.Errorf("init client: %w", err)
	}

	var urlArg string
	_, err = http.ReadResponse(bufio.NewReader(params.Input), nil)
	switch {
	case errors.Is(err, nil):
		// url must present here
		if len(params.Args) == 0 {
			return fmt.Errorf("response has been read but no url provided")
		}
		urlArg = params.Args[len(params.Args)-1] // go toolchain appends url as last arg
	case errors.Is(err, io.EOF):
		return nil // first run
	default:
		return fmt.Errorf("read response: %w", err)
	}

	// find creds for url and if present push them to output
	u, err := url.Parse(urlArg)
	if err != nil {
		return fmt.Errorf("parse url: %w", err)
	}

	var keepassError *gkpxc.ErrorResponse

	logins, err := client.GetLogins(ctx, gkpxc.GetLoginsRequest{URL: u.String()})
	switch {
	case errors.Is(err, nil):
		// pass
	case errors.As(err, &keepassError) && keepassError.Code == 15:
		// not found, just exit
		return nil
	default:
		return fmt.Errorf("request logins: %w", err)
	}

	var outputEntries []OutputEntry
	if params.TransformEntries != nil {
		outputEntries, err = params.TransformEntries(logins.Entries)
	} else {
		outputEntries = transformEntries(logins.Entries, u)
	}
	if err != nil {
		return fmt.Errorf("transform entries: %w", err)
	}

	var sb bytes.Buffer
	for i, outputEntry := range outputEntries {
		sb.Reset()

		// urls, one per line
		for _, u := range outputEntry.URLs {
			sb.WriteString(u)
			sb.WriteByte('\n')
		}

		// blank line
		sb.WriteByte('\n')

		// headers
		if err = outputEntry.Headers.Write(&sb); err != nil {
			return fmt.Errorf("write headers %d: %w", i, err)
		}

		// blank line
		sb.WriteByte('\n')

		// push to output
		if _, err = sb.WriteTo(params.Output); err != nil {
			return fmt.Errorf("output %d: %w", i, err)
		}
	}

	return nil
}

func initClient(ctx context.Context, kr keyring.Keyring) (*gkpxc.Client, error) {
	client, err := gkpxc.NewClient(ctx)
	if err != nil {
		return client, fmt.Errorf("keepassxc connect failed: %w", err)
	}

	dbHash, err := client.GetDatabaseHash(ctx, true)
	if err != nil {
		return client, fmt.Errorf("get database hash failed: %w", err)
	}

	secret, err := kr.Get(dbHash.Hash)
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
			return nil, fmt.Errorf("association failed: %w", err)
		}

		serialized, err := json.Marshal(client.AssociationCredentials())
		if err != nil {
			return nil, fmt.Errorf("serialize association credentials failed: %w", err)
		}

		if err = kr.Set(keyring.Item{Key: dbHash.Hash, Data: serialized}); err != nil {
			return nil, fmt.Errorf("store association credentials failed: %w", err)
		}
	default:
		return nil, fmt.Errorf("association key get failed: %w", err)
	}

	return client, nil
}

func transformEntries(entries []gkpxc.LoginEntry, u *url.URL) []OutputEntry {
	// go toolchain expects url, but we keepassxc does not return url specified in record
	// so return root url for given host
	// this _may_ break in some cases (i.e. different accounts for subpaths)
	// but should work fine most of the times

	entry := entries[0]

	headers := http.Header{
		"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte(entry.Login+":"+entry.Password))},
	}

	return []OutputEntry{
		{
			URLs: []string{
				(&url.URL{
					Scheme: u.Scheme,
					Host:   u.Host,
				}).String(),
			},
			Headers: headers,
		},
	}
}
