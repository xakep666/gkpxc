package gkpxc

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"

	"golang.org/x/crypto/nacl/box"
)

// SocketName is a standard KeepassXC socket name.
const SocketName = "org.keepassxc.KeePassXC.BrowserServer"

const (
	NonceSize = 24
	KeySize   = 32
)

var (
	// ErrDecryptFailed returns when response can't be decrypted.
	ErrDecryptFailed = fmt.Errorf("response decrypt failed")

	// ErrInvalidNonce returned if invalid nonce received in response.
	ErrInvalidNonce = fmt.Errorf("invalid nonce")

	// ErrClosing may be sent if operation interrupted by closing.
	ErrClosing = fmt.Errorf("closing")

	// ErrNotAssociated returned if method requires association with database but no credentials present.
	// In this case Client.Associate or Client.SetAssociationCredentials must be used.
	ErrNotAssociated = fmt.Errorf("not associated")
)

// AssociationCredentials holds KeepassXC association credentials.
type AssociationCredentials struct {
	ID, Hash, Version     string // returned from KeepassXC
	PrivateKey, PublicKey [KeySize]byte
}

type msgErrPair struct {
	Message
	error
}

// Client is a KeepassXC protocol client.
type Client struct {
	conn      net.Conn
	closeConn bool

	clientID              *[NonceSize]byte
	privateKey, publicKey *[KeySize]byte
	sharedKey             *[KeySize]byte // computed after handshake
	associationCred       *AssociationCredentials

	// to support asynchronous signals from KeepassXC
	stop               chan struct{}   // broadcast for readers and writers of channels below
	requests           chan Message    // main->read
	responses          chan msgErrPair // write->main
	errorHandlers      []func(err error)
	lockChangeHandlers []func(locked bool)
}

// NewClient creates KeepassXC client. By default, it connects to internal socket/pipe and associates as new client.
// Typical workflow:
// 1. Request database hash using Client.GetDatabaseHash.
// 2. Lookup association credentials by received hash and use it (Client.SetAssociationCredentials).
// 3. Request a new association if such credentials was not found on step 2 using Client.Associate.
//		Then get them using Client.AssociationCredentials and store in safe place.
// 4. Optionally subscribe to asynchronous events.
// 5. Make requests.
// 6. Close client.
func NewClient(ctx context.Context, opts ...ClientOption) (*Client, error) {
	cfg := clientConfig{}
	for _, o := range opts {
		o(&cfg)
	}

	conn := cfg.customConn
	closeConn := false

	if conn == nil {
		var err error
		conn, err = connect(ctx)
		if err != nil {
			return nil, fmt.Errorf("connect: %w", err)
		}

		closeConn = true
	}

	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate keypair: %w", err)
	}

	clientID, err := generateNonce()
	if err != nil {
		return nil, fmt.Errorf("generate client id: %w", err)
	}

	client := &Client{
		conn:      conn,
		closeConn: closeConn,

		clientID:   clientID,
		privateKey: priv,
		publicKey:  pub,

		stop:               make(chan struct{}),
		requests:           make(chan Message),
		responses:          make(chan msgErrPair),
		errorHandlers:      cfg.errorHandlers,
		lockChangeHandlers: cfg.lockChangeHandlers,
	}

	go client.write()
	go client.read()

	if err = client.handshake(ctx); err != nil {
		defer client.Close()
		return nil, fmt.Errorf("handshake: %w", err)
	}

	return client, nil
}

func (c *Client) handshake(ctx context.Context) error {
	if c.sharedKey != nil {
		return nil // handshake already done
	}

	nonce, err := generateNonce()
	if err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}

	resp, err := c.exchange(ctx, Message{
		Action:    "change-public-keys",
		Nonce:     (*nonce)[:],
		ClientID:  (*c.clientID)[:],
		PublicKey: (*c.publicKey)[:],
	})
	if err != nil {
		return err
	}

	c.sharedKey = new([KeySize]byte)
	box.Precompute(c.sharedKey, (*[KeySize]byte)(resp.PublicKey), c.privateKey)

	return nil
}

// GetDatabaseHash may be used to lookup existing association credentials for database.
func (c *Client) GetDatabaseHash(ctx context.Context, triggerUnlock bool) (GetDatabaseHashResponse, error) {
	var resp GetDatabaseHashResponse

	if err := c.exchangeEncrypted(ctx, triggerUnlock, GetDatabaseHashRequest{}, &resp); err != nil {
		return GetDatabaseHashResponse{}, err
	}

	return resp, nil
}

// Associate requests a new association from KeepassXC and saves credentials.
func (c *Client) Associate(ctx context.Context) error {
	var resp AssociateResponse

	pubID, privID, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate keypair: %w", err)
	}

	err = c.exchangeEncrypted(ctx, false, AssociateRequest{
		Key:   (*c.publicKey)[:],
		IDKey: (*pubID)[:],
	}, &resp)
	if err != nil {
		return err
	}

	c.associationCred = &AssociationCredentials{
		ID:         resp.ID,
		Hash:       resp.Hash,
		Version:    resp.Version,
		PublicKey:  *pubID,
		PrivateKey: *privID,
	}

	return nil
}

// AssociationCredentials returns stored associations credentials. They're valid only for one database.
func (c *Client) AssociationCredentials() *AssociationCredentials { return c.associationCred }

// SetAssociationCredentials can be used to set association existing association credentials.
func (c *Client) SetAssociationCredentials(cred *AssociationCredentials) { c.associationCred = cred }

// TestAssociate tests association with database. Association credentials must present.
func (c *Client) TestAssociate(ctx context.Context) error {
	if c.associationCred == nil {
		return ErrNotAssociated
	}

	return c.exchangeEncrypted(ctx, false, TestAssociateRequest{
		ID:  c.associationCred.ID,
		Key: c.associationCred.PublicKey[:],
	}, &TestAssociateResponse{})
}

// GetDatabaseGroups returns database groups. Association credentials must present.
func (c *Client) GetDatabaseGroups(ctx context.Context) (DatabaseGroupsResponse, error) {
	if err := c.TestAssociate(ctx); err != nil {
		return DatabaseGroupsResponse{}, err
	}

	var resp DatabaseGroupsResponse
	err := c.exchangeEncrypted(ctx, false, DatabaseGroupsRequest{}, &resp)
	if err != nil {
		return DatabaseGroupsResponse{}, err
	}

	return resp, nil
}

// CreateNewGroup creates new group and returns it's uuid. Association credentials must present.
func (c *Client) CreateNewGroup(ctx context.Context, req CreateNewGroupRequest) (CreateNewGroupResponse, error) {
	if err := c.TestAssociate(ctx); err != nil {
		return CreateNewGroupResponse{}, err
	}

	var resp CreateNewGroupResponse
	if err := c.exchangeEncrypted(ctx, false, req, &resp); err != nil {
		return CreateNewGroupResponse{}, err
	}

	return resp, nil
}

// GetLogins queries for database entries by URL.
func (c *Client) GetLogins(ctx context.Context, req GetLoginsRequest) (GetLoginsResponse, error) {
	if err := c.TestAssociate(ctx); err != nil {
		return GetLoginsResponse{}, err
	}

	// put our credentials first
	req.Keys = append([]LoginKey{{
		ID:  c.associationCred.ID,
		Key: c.associationCred.PublicKey[:],
	}}, req.Keys...)

	var resp GetLoginsResponse
	if err := c.exchangeEncrypted(ctx, false, req, &resp); err != nil {
		return GetLoginsResponse{}, err
	}

	return resp, nil
}

// SetLogin creates or updates existing login.
func (c *Client) SetLogin(ctx context.Context, req SetLoginRequest) error {
	if err := c.TestAssociate(ctx); err != nil {
		return err
	}

	return c.exchangeEncrypted(ctx, false, req, &SetLoginResponse{})
}

// DeleteEntry deletes entry.
func (c *Client) DeleteEntry(ctx context.Context, req DeleteEntryRequest) error {
	if err := c.TestAssociate(ctx); err != nil {
		return err
	}

	return c.exchangeEncrypted(ctx, false, req, &DeleteEntryResponse{})
}

// GeneratePassword requests to show generate password dialog.
func (c *Client) GeneratePassword(ctx context.Context) error {
	if err := c.TestAssociate(ctx); err != nil {
		return err
	}

	return c.exchangeEncrypted(ctx, false, GeneratePasswordRequest{}, &GeneratePasswordResponse{})
}

// LockDatabase locks current database.
func (c *Client) LockDatabase(ctx context.Context) error {
	if err := c.TestAssociate(ctx); err != nil {
		return err
	}

	return c.exchangeEncrypted(ctx, false, LockDatabaseRequest{}, &LockDatabaseResponse{})
}

// GetTOTP requests current TOTP value for entry.
func (c *Client) GetTOTP(ctx context.Context, req GetTOTPRequest) (GetTOTPResponse, error) {
	if err := c.TestAssociate(ctx); err != nil {
		return GetTOTPResponse{}, err
	}

	var resp GetTOTPResponse
	if err := c.exchangeEncrypted(ctx, false, req, &resp); err != nil {
		return GetTOTPResponse{}, err
	}

	return resp, nil
}

// RequestAutoType requests password auto type by URL or TLD.
func (c *Client) RequestAutoType(ctx context.Context, req AutoTypeRequest) error {
	if err := c.TestAssociate(ctx); err != nil {
		return err
	}

	return c.exchangeEncrypted(ctx, false, req, &AutoTypeResponse{})
}

func (c *Client) write() {
	for {
		select {
		case <-c.stop:
			return
		case req := <-c.requests:
			err := json.NewEncoder(c.conn).Encode(req)
			if err == nil {
				break
			}

			// transfer error to caller
			select {
			case <-c.stop:
				return
			case c.responses <- msgErrPair{error: err}:
			}
		}
	}
}

func (c *Client) read() {
	decoder := json.NewDecoder(c.conn)
	for {
		var (
			msg Message
			err error
		)

		if err = decoder.Decode(&msg); err == nil {
			err = msg.asError()
		}

		switch msg.Action {
		case "database-locked", "database-unlocked":
			locked := msg.Action == "database-locked"
			for _, h := range c.lockChangeHandlers {
				go h(locked)
			}

			continue
		case "":
			if err != nil {
				for _, h := range c.errorHandlers {
					go h(err)
				}
			}
		}

		select {
		case <-c.stop:
			return
		case c.responses <- msgErrPair{Message: msg, error: err}:
		}
	}
}

func (c *Client) exchange(ctx context.Context, req Message) (Message, error) {
	select {
	case <-c.stop:
		return Message{}, ErrClosing
	case c.requests <- req:
		// pass
	case <-ctx.Done():
		return Message{}, ctx.Err()
	}

	var resp msgErrPair

	select {
	case <-c.stop:
		return Message{}, ErrClosing
	case resp = <-c.responses:
	case <-ctx.Done():
		return Message{}, ctx.Err()
	}

	if resp.error != nil {
		return Message{}, resp.error
	}

	if !bytes.Equal(incrementNonce(req.Nonce), resp.Nonce) {
		return Message{}, ErrInvalidNonce
	}

	return resp.Message, nil
}

type plainReq interface {
	Action() string
}

type plainResp interface {
	asError() error
}

func (c *Client) exchangeEncrypted(ctx context.Context, triggerUnlock bool, req plainReq, resp plainResp) error {
	nonce, err := generateNonce()
	if err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}

	// stdlib-only way to add "action" field

	var reqMap map[string]interface{}

	msg, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	if err = json.Unmarshal(msg, &reqMap); err != nil {
		return fmt.Errorf("unmarshal request: %w", err)
	}

	reqMap["action"] = req.Action()

	msg, err = json.Marshal(reqMap)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	res, err := c.exchange(ctx, Message{
		Action:        req.Action(),
		Message:       box.SealAfterPrecomputation(nil, msg, nonce, c.sharedKey),
		Nonce:         (*nonce)[:],
		ClientID:      (*c.clientID)[:],
		TriggerUnlock: triggerUnlock,
	})
	if err != nil {
		return err
	}

	decrypted, ok := box.OpenAfterPrecomputation(nil, res.Message, (*[NonceSize]byte)(res.Nonce), c.sharedKey)
	if !ok {
		return ErrDecryptFailed
	}

	if err = json.Unmarshal(decrypted, resp); err != nil {
		return fmt.Errorf("unmarshal response: %w", err)
	}

	return resp.asError()
}

// Close stops sending and receiving messages.
func (c *Client) Close() error {
	close(c.stop)

	if c.closeConn {
		return c.conn.Close()
	}

	return nil
}

func generateNonce() (*[NonceSize]byte, error) {
	var ret [NonceSize]byte
	_, err := rand.Read(ret[:])
	return &ret, err
}

func incrementNonce(nonce []byte) []byte {
	ret := append([]byte{}, nonce...)

	c := uint16(1) // to save carry bits
	for i := range ret {
		c += uint16(ret[i])
		ret[i] = byte(c)
		c >>= 8
	}

	return ret
}
