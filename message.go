package gkpxc

import (
	"fmt"
)

// ErrorResponse returned as error if KeepassXC responds with error.
type ErrorResponse struct {
	Text string
	Code int
}

func (e *ErrorResponse) Error() string {
	return fmt.Sprintf("keepassxc: %s (%d)", e.Text, e.Code)
}

type ErrorFields struct {
	Success *bool  `json:"success,string,omitempty"` // sometimes omitted
	Text    string `json:"error,omitempty"`
	Code    int    `json:"errorCode,string,omitempty"`
}

func (f ErrorFields) asError() error {
	if f.Success != nil && *f.Success {
		return nil
	}

	if f.Success == nil && f.Code == 0 {
		return nil
	}

	return &ErrorResponse{Text: f.Text, Code: f.Code}
}

// Message represents message used to talk with KeepassXC.
type Message struct {
	ErrorFields

	// Action is a message type. I.e. "change-public-keys", "associate", ...
	Action string `json:"action"`

	// Message is base64-encoded encrypted message.
	Message []byte `json:"message,omitempty"`

	// Nonce is base64-encoded nonce.
	Nonce []byte `json:"nonce"`

	// ClientID needed to identify client if multiple ones used.
	ClientID []byte `json:"clientID"`

	// Version is KeepassXC version.
	Version string `json:"version,omitempty"`

	// PublicKey is base64-encoded public key used during handshake (Action="change-public-keys").
	PublicKey []byte `json:"publicKey,omitempty"`

	// TriggerUnlock requests database unlock.
	TriggerUnlock bool `json:"triggerUnlock,omitempty,string"`
}

// GetDatabaseHashRequest represents request for database hash.
type GetDatabaseHashRequest struct{}

func (GetDatabaseHashRequest) Action() string { return "get-databasehash" }

// GetDatabaseHashResponse returned as response for GetDatabaseHashRequest.
type GetDatabaseHashResponse struct {
	ErrorFields

	Hash    string `json:"hash"`
	Version string `json:"version"`
}

// AssociateRequest represents new client association request.
type AssociateRequest struct {
	// Key is a public key from handshake.
	Key []byte `json:"key"`

	// IDKey is a public key for association.
	IDKey []byte `json:"idKey"`
}

func (AssociateRequest) Action() string { return "associate" }

// AssociateResponse returned on successful association.
type AssociateResponse struct {
	ErrorFields

	ID      string `json:"id"`
	Hash    string `json:"hash"`
	Version string `json:"version"`
}

// TestAssociateRequest represents client association test request.
type TestAssociateRequest struct {
	// ID is database id from association.
	ID string `json:"id"`

	// Key is a public key for association.
	Key []byte `json:"key"`
}

func (TestAssociateRequest) Action() string { return "test-associate" }

// TestAssociateResponse returned on successful association test.
type TestAssociateResponse struct {
	ErrorFields

	ID      string `json:"id"`
	Hash    string `json:"hash"`
	Version string `json:"version"`
}

// DatabaseGroup is item of group hierarchy.
type DatabaseGroup struct {
	Name     string          `json:"name"`
	UUID     string          `json:"uuid"`
	Children []DatabaseGroup `json:"children"`
}

// DatabaseGroupsRequest request list of group hierarchy.
type DatabaseGroupsRequest struct{}

func (DatabaseGroupsRequest) Action() string { return "get-database-groups" }

type GroupsEmbedded struct {
	Groups []DatabaseGroup `json:"groups"`
}

// DatabaseGroupsResponse contains group hierarchy present in database.
type DatabaseGroupsResponse struct {
	ErrorFields

	DefaultGroup            string         `json:"defaultGroup"`
	DefaultGroupAlwaysAllow bool           `json:"defaultGroupAlwaysAllow"`
	Groups                  GroupsEmbedded `json:"groups"`
}

// CreateNewGroupRequest represents new group creation request.
type CreateNewGroupRequest struct {
	Name string `json:"groupName"`
}

func (CreateNewGroupRequest) Action() string { return "create-new-group" }

// CreateNewGroupResponse contains newly created group id.
type CreateNewGroupResponse struct {
	ErrorFields

	Name string `json:"name"`
	UUID string `json:"uuid"`
}

type LoginKey struct {
	// ID is client id from association.
	ID string `json:"id"`

	// Key is client public key used for association.
	Key []byte `json:"key"`
}

// GetLoginsRequest represents request for logins.
type GetLoginsRequest struct {
	// URL credentials looked for.
	URL string `json:"url"`

	SubmitURL string     `json:"submitUrl"`
	HTTPAuth  string     `json:"httpAuth"`
	Keys      []LoginKey `json:"keys"`
}

func (GetLoginsRequest) Action() string { return "get-logins" }

// LoginEntry is a single database entry.
type LoginEntry struct {
	UUID string `json:"uuid"`

	// Name is how it named in database.
	Name string `json:"name"`

	// Login contains user name.
	Login string `json:"login"`

	// Password contains password.
	Password string `json:"password"`

	// Expired is set when password expired according to entry expiration time.
	Expired bool `json:"expired,string"`
}

// GetLoginsResponse contains found logins.
type GetLoginsResponse struct {
	ErrorFields

	Count   int          `json:"count"`
	Entries []LoginEntry `json:"entries"`
}

// SetLoginRequest represents create or update login request.
type SetLoginRequest struct {
	URL             string `json:"url"`
	SubmitURL       string `json:"submitUrl"`
	Login           string `json:"login"`
	Password        string `json:"password"`
	Group           string `json:"group"`
	GroupUUID       string `json:"groupUuid"`
	UUID            string `json:"uuid"` // create new if empty
	DownloadFavicon bool   `json:"downloadFavicon,string"`
}

func (SetLoginRequest) Action() string { return "set-login" }

// SetLoginResponse returned on SetLoginRequest.
type SetLoginResponse struct {
	ErrorFields
}

// DeleteEntryRequest requests deletion entry by uuid.
type DeleteEntryRequest struct {
	UUID string `json:"uuid"`
}

func (DeleteEntryRequest) Action() string { return "delete-entry" }

// DeleteEntryResponse returned on DeleteEntryRequest.
type DeleteEntryResponse struct {
	ErrorFields
}

// GeneratePasswordRequest requests to show generate password dialog.
type GeneratePasswordRequest struct{}

func (GeneratePasswordRequest) Action() string { return "generate-password" }

// GeneratePasswordResponse returned on GeneratePasswordRequest.
type GeneratePasswordResponse struct {
	ErrorFields
}

// LockDatabaseRequest requests to lock database.
type LockDatabaseRequest struct{}

func (LockDatabaseRequest) Action() string { return "lock-database" }

// LockDatabaseResponse returned on LockDatabaseRequest.
type LockDatabaseResponse struct {
	ErrorFields
}

// GetTOTPRequest requests current TOTP for entry.
type GetTOTPRequest struct {
	// UUID is entry uuid.
	UUID string `json:"uuid"`
}

func (GetTOTPRequest) Action() string { return "get-totp" }

// GetTOTPResponse contains current TOTP for entry.
type GetTOTPResponse struct {
	ErrorFields

	TOTP string `json:"totp"`
}

// AutoTypeRequest requests auto type by URL.
type AutoTypeRequest struct {
	// Search is a search string for entry (URL or TLD).
	Search string `json:"search"`
}

func (AutoTypeRequest) Action() string { return "request-autotype" }

// AutoTypeResponse returned on AutoTypeRequest.
type AutoTypeResponse struct {
	ErrorFields
}
