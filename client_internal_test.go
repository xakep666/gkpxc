package gkpxc

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

func TestClient_HandshakeFailed(t *testing.T) {
	cc, sc := net.Pipe()
	go func() {
		json.NewDecoder(sc).Decode(new(interface{}))
		json.NewEncoder(sc).Encode(Message{ErrorFields: ErrorFields{Text: "test-err", Code: 10}})
		sc.Close()
	}()

	var actualErr *ErrorResponse
	_, err := NewClient(context.Background(), WithConn(cc))
	if !errors.As(err, &actualErr) {
		t.Fatalf("Got unexpected error %s, expected ErrorResponse", err)
	}

	expectError := ErrorResponse{Text: "test-err", Code: 10}
	if *actualErr != expectError {
		t.Fatalf("Got unexpected error value %+v, expected %+v", *actualErr, expectError)
	}
}

func TestClient_NotAssociated(t *testing.T) {
	cc, sc := net.Pipe()
	go func() {
		var req Message
		json.NewDecoder(sc).Decode(&req)
		json.NewEncoder(sc).Encode(Message{
			Action:    "change-public-keys",
			PublicKey: bytes.Repeat([]byte{1}, KeySize),
			Nonce:     incrementNonce(req.Nonce),
		})
		sc.Close()
	}()

	c, err := NewClient(context.Background(), WithConn(cc))
	if err != nil {
		t.Fatalf("Got error %s, expected nil", err)
	}

	defer c.Close()

	if err = c.TestAssociate(context.Background()); !errors.Is(err, ErrNotAssociated) {
		t.Fatalf("Expected ErrNotAssociated, got %s", err)
	}
}

func TestClient_InvalidNonce(t *testing.T) {
	cc, sc := net.Pipe()
	go func() {
		var req Message
		json.NewDecoder(sc).Decode(&req)
		json.NewEncoder(sc).Encode(Message{
			Action:    "change-public-keys",
			PublicKey: bytes.Repeat([]byte{1}, KeySize),
		})
		sc.Close()
	}()

	_, err := NewClient(context.Background(), WithConn(cc))
	if !errors.Is(err, ErrInvalidNonce) {
		t.Fatalf("Got error %s, expected ErrInvalidNonce", err)
	}
}

func TestClient_DecryptFailed(t *testing.T) {
	cc, sc := net.Pipe()
	go func() {
		dec := json.NewDecoder(sc)

		var req Message
		dec.Decode(&req)
		json.NewEncoder(sc).Encode(Message{
			Action:    "change-public-keys",
			PublicKey: bytes.Repeat([]byte{1}, KeySize),
			Nonce:     incrementNonce(req.Nonce),
		})

		dec.Decode(&req)
		json.NewEncoder(sc).Encode(Message{
			Action:  "associate",
			Nonce:   incrementNonce(req.Nonce),
			Message: bytes.Repeat([]byte{1, 2}, 20),
		})
		sc.Close()
	}()

	c, err := NewClient(context.Background(), WithConn(cc))
	if err != nil {
		t.Fatalf("Got error %s, expected nil", err)
	}

	defer c.Close()

	if err = c.Associate(context.Background()); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("Expected ErrDecryptFailed, got %s", err)
	}
}

func TestClient_Associates(t *testing.T) {
	cc, sc := net.Pipe()
	go func() {
		pub, priv, _ := box.GenerateKey(rand.Reader)
		var peerPub *[KeySize]byte
		dec := json.NewDecoder(sc)

		var req Message
		dec.Decode(&req)
		peerPub = (*[KeySize]byte)(req.PublicKey)
		json.NewEncoder(sc).Encode(Message{
			Action:    "change-public-keys",
			PublicKey: (*pub)[:],
			Nonce:     incrementNonce(req.Nonce),
		})

		dec.Decode(&req)
		newNonce := incrementNonce(req.Nonce)
		json.NewEncoder(sc).Encode(Message{
			Action: "associate",
			Nonce:  newNonce,
			Message: box.Seal(nil,
				[]byte(`{"action": "associate", "id": "test-id", "hash": "test-hash", "version": "1234"}`),
				(*[NonceSize]byte)(newNonce),
				peerPub,
				priv,
			),
		})
		sc.Close()
	}()

	c, err := NewClient(context.Background(), WithConn(cc))
	if err != nil {
		t.Fatalf("Got error %s, expected nil", err)
	}

	defer c.Close()

	if err = c.Associate(context.Background()); err != nil {
		t.Fatalf("Expected nil error, got %s", err)
	}

	if c.AssociationCredentials().ID != "test-id" {
		t.Fatalf("Expected id 'test-id', got %s", c.AssociationCredentials().ID)
	}
}

func TestClient_Handles_async_error(t *testing.T) {
	var (
		wg   sync.WaitGroup
		errs []error
	)

	cc, sc := net.Pipe()
	go func() {
		dec := json.NewDecoder(sc)

		var req Message
		dec.Decode(&req)
		json.NewEncoder(sc).Encode(Message{
			Action:    "change-public-keys",
			PublicKey: bytes.Repeat([]byte{1}, KeySize),
			Nonce:     incrementNonce(req.Nonce),
		})

		sc.Write([]byte("{123"))

		sc.Close()
	}()

	wg.Add(1)
	c, err := NewClient(context.Background(), WithConn(cc), WithAsyncErrorHandler(func(err error) {
		errs = append(errs, err)
		wg.Done()
	}))
	if err != nil {
		t.Fatalf("Got error %s, expected nil", err)
	}

	defer c.Close()

	wg.Wait()
	if len(errs) != 1 || errs[0] == nil {
		t.Fatalf("One error expected, got %+v", errs)
	}
}

func TestClient_Handles_signal(t *testing.T) {
	var (
		wg            sync.WaitGroup
		lockedSignals []bool
	)

	cc, sc := net.Pipe()
	go func() {
		dec := json.NewDecoder(sc)

		var req Message
		dec.Decode(&req)
		json.NewEncoder(sc).Encode(Message{
			Action:    "change-public-keys",
			PublicKey: bytes.Repeat([]byte{1}, KeySize),
			Nonce:     incrementNonce(req.Nonce),
		})

		json.NewEncoder(sc).Encode(Message{Action: "database-locked"})

		sc.Close()
	}()

	wg.Add(1)
	c, err := NewClient(context.Background(), WithConn(cc), WithLockChangeHandler(func(locked bool) {
		lockedSignals = append(lockedSignals, locked)
		wg.Done()
	}))
	if err != nil {
		t.Fatalf("Got error %s, expected nil", err)
	}

	defer c.Close()

	wg.Wait()
	if len(lockedSignals) != 1 || !lockedSignals[0] {
		t.Fatalf("One locked signal expected, got %+v", lockedSignals)
	}
}
