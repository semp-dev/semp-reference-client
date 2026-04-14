// Package client provides the core SEMP client: connection, handshake,
// session lifecycle, sending, receiving, and rekeying.
package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/handshake"
	"semp.dev/semp-go/keys"
	"semp.dev/semp-go/session"
	"semp.dev/semp-go/transport"
	"semp.dev/semp-go/transport/h2"
	"semp.dev/semp-go/transport/ws"

	"semp.dev/semp-reference-client/internal/config"
	"semp.dev/semp-reference-client/internal/store"
)

// Client manages a single SEMP session with the user's home server.
type Client struct {
	Cfg   *config.Config
	Store *store.SQLiteStore
	Suite crypto.Suite
	Log   *slog.Logger

	conn    transport.Conn
	session *session.Session

	// Cached key fingerprints loaded at Connect time.
	identityFP   keys.Fingerprint
	encryptionFP keys.Fingerprint
}

// New creates a client. Call Connect and then Handshake (or
// ConnectAndHandshake) before using Send/Fetch/etc.
func New(cfg *config.Config, s *store.SQLiteStore, log *slog.Logger) *Client {
	suite := crypto.LookupSuite(crypto.SuiteID(cfg.Suite))
	if suite == nil {
		suite = crypto.SuitePQ // default to post-quantum
	}
	return &Client{
		Cfg:   cfg,
		Store: s,
		Suite: suite,
		Log:   log,
	}
}

// Register generates keys locally (if needed) and registers the public
// keys with the home server via POST /v1/register. Returns the server's
// domain signing and encryption keys for local caching.
func (c *Client) Register(ctx context.Context, password string) error {
	// Generate keys locally if not present.
	has, _ := c.Store.HasUserKeys(c.Cfg.Identity)
	if !has {
		idPub, idPriv, err := c.Suite.Signer().GenerateKeyPair()
		if err != nil {
			return fmt.Errorf("client: generate identity key: %w", err)
		}
		c.Store.PutUserKeyPair(c.Cfg.Identity, keys.TypeIdentity, "ed25519", idPub, idPriv)

		// Encryption keys use the suite's KEM so that post-quantum suites
		// generate hybrid keys for PQ-protected envelope wrapping.
		encPub, encPriv, err := c.Suite.KEM().GenerateKeyPair()
		if err != nil {
			return fmt.Errorf("client: generate encryption key: %w", err)
		}
		c.Store.PutUserKeyPair(c.Cfg.Identity, keys.TypeEncryption, string(c.Suite.ID()), encPub, encPriv)
		c.Log.Info("generated keys locally")
	}

	// Load public keys for registration.
	idPub, idFP, err := c.Store.LoadUserPublicKey(c.Cfg.Identity, keys.TypeIdentity)
	if err != nil || idFP == "" {
		return fmt.Errorf("client: no identity key found")
	}
	encPub, encFP, err := c.Store.LoadUserPublicKey(c.Cfg.Identity, keys.TypeEncryption)
	if err != nil || encFP == "" {
		return fmt.Errorf("client: no encryption key found")
	}

	// Build HTTPS URL from the WSS server URL.
	registerURL := c.Cfg.Server
	registerURL = strings.Replace(registerURL, "wss://", "https://", 1)
	registerURL = strings.Replace(registerURL, "ws://", "http://", 1)
	// Strip the path (e.g. /v1/ws) and use /v1/register.
	if idx := strings.Index(registerURL, "/v1/"); idx > 0 {
		registerURL = registerURL[:idx]
	}
	registerURL += "/v1/register"

	// POST registration request.
	reqBody := registerRequest{
		Address:  c.Cfg.Identity,
		Password: password,
		IdentityKey: registerKey{
			Algorithm: "ed25519",
			PublicKey: base64.StdEncoding.EncodeToString(idPub),
		},
		EncryptionKey: registerKey{
			Algorithm: string(c.Suite.ID()),
			PublicKey: base64.StdEncoding.EncodeToString(encPub),
		},
	}
	body, _ := json.Marshal(reqBody)
	resp, err := http.Post(registerURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("client: register: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("client: register: server returned %d", resp.StatusCode)
	}

	var regResp registerResponse
	if err := json.NewDecoder(resp.Body).Decode(&regResp); err != nil {
		return fmt.Errorf("client: register: decode response: %w", err)
	}

	// Cache the server's domain keys locally.
	if regResp.DomainSigningKey != nil {
		domPub, err := base64.StdEncoding.DecodeString(regResp.DomainSigningKey.PublicKey)
		if err == nil {
			c.Store.PutDomainKeyPair(c.Cfg.Domain, "signing", regResp.DomainSigningKey.Algorithm, domPub, nil)
			c.Log.Info("cached domain signing key", "fingerprint", regResp.DomainSigningKey.KeyID)
		}
	}
	if regResp.DomainEncryptionKey != nil {
		domEncPub, err := base64.StdEncoding.DecodeString(regResp.DomainEncryptionKey.PublicKey)
		if err == nil {
			c.Store.PutDomainKeyPair(c.Cfg.Domain, "encryption", regResp.DomainEncryptionKey.Algorithm, domEncPub, nil)
			c.Log.Info("cached domain encryption key", "fingerprint", regResp.DomainEncryptionKey.KeyID)
		}
	}

	c.Log.Info("registered with server",
		"address", c.Cfg.Identity,
		"identity_fp", idFP,
		"encryption_fp", encFP,
	)
	return nil
}

type registerRequest struct {
	Address       string      `json:"address"`
	Password      string      `json:"password"`
	IdentityKey   registerKey `json:"identity_key"`
	EncryptionKey registerKey `json:"encryption_key"`
}

type registerKey struct {
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"`
}

type registerResponse struct {
	Status              string           `json:"status"`
	DomainSigningKey    *registerKeyEntry `json:"domain_signing_key,omitempty"`
	DomainEncryptionKey *registerKeyEntry `json:"domain_encryption_key,omitempty"`
}

type registerKeyEntry struct {
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"`
	KeyID     string `json:"key_id"`
}

// Connect opens a WebSocket connection to the home server.
func (c *Client) Connect(ctx context.Context) error {
	// Load user key fingerprints from store.
	_, idFP, err := c.Store.LoadUserPrivateKey(c.Cfg.Identity, keys.TypeIdentity)
	if err != nil {
		return fmt.Errorf("client: load identity key: %w", err)
	}
	if idFP == "" {
		return fmt.Errorf("client: no identity key found for %s — run 'register' first", c.Cfg.Identity)
	}
	c.identityFP = idFP

	_, encFP, err := c.Store.LoadUserPrivateKey(c.Cfg.Identity, keys.TypeEncryption)
	if err != nil {
		return fmt.Errorf("client: load encryption key: %w", err)
	}
	c.encryptionFP = encFP

	// Dial using the appropriate transport based on URL scheme.
	var conn transport.Conn
	var dialErr error
	server := c.Cfg.Server
	if strings.HasPrefix(server, "wss://") || strings.HasPrefix(server, "ws://") {
		t := ws.NewWithConfig(ws.Config{AllowInsecure: c.Cfg.TLS.Insecure})
		conn, dialErr = t.Dial(ctx, server)
	} else if strings.HasPrefix(server, "https://") || strings.HasPrefix(server, "http://") {
		t := h2.NewWithConfig(h2.PersistentConfig{
			Config: h2.Config{AllowInsecure: c.Cfg.TLS.Insecure},
		})
		conn, dialErr = t.Dial(ctx, server)
	} else {
		return fmt.Errorf("client: unsupported server URL scheme: %s", server)
	}
	if dialErr != nil {
		return fmt.Errorf("client: dial %s: %w", server, dialErr)
	}
	c.conn = conn
	c.Log.Info("connected", "server", c.Cfg.Server)
	return nil
}

// Handshake runs the four-message SEMP handshake and establishes an
// authenticated session.
func (c *Client) Handshake(ctx context.Context) error {
	if c.conn == nil {
		return fmt.Errorf("client: not connected")
	}

	cli := handshake.NewClient(handshake.ClientConfig{
		Suite:         c.Suite,
		Store:         c.Store,
		Identity:      c.Cfg.Identity,
		IdentityKeyID: c.identityFP,
		ServerDomain:  c.Cfg.Domain,
	})
	defer cli.Erase()

	sess, err := handshake.RunClient(ctx, c.conn, cli)
	if err != nil {
		return fmt.Errorf("client: handshake: %w", err)
	}
	c.session = sess
	c.Log.Info("session established",
		"session_id", sess.ID,
		"ttl", sess.TTL,
		"expires_at", sess.ExpiresAt)
	return nil
}

// ConnectAndHandshake is a convenience that dials and handshakes in one call.
func (c *Client) ConnectAndHandshake(ctx context.Context) error {
	if err := c.Connect(ctx); err != nil {
		return err
	}
	return c.Handshake(ctx)
}

// Session returns the current session, or nil if not established.
func (c *Client) Session() *session.Session { return c.session }

// Conn returns the underlying transport connection.
func (c *Client) Conn() transport.Conn { return c.conn }

// Close tears down the session and connection.
func (c *Client) Close() {
	if c.session != nil {
		c.session.Erase()
		c.session = nil
	}
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
}

// recipientPrivateKeys builds the candidate list for OpenBriefAny / OpenEnclosureAny
// from the user's local encryption key.
func (c *Client) recipientPrivateKeys() ([]RecipientCandidate, error) {
	priv, fp, err := c.Store.LoadUserPrivateKey(c.Cfg.Identity, keys.TypeEncryption)
	if err != nil {
		return nil, fmt.Errorf("client: load encryption private key: %w", err)
	}
	if fp == "" {
		return nil, fmt.Errorf("client: no encryption key found for %s", c.Cfg.Identity)
	}
	pub, _, err := c.Store.LoadUserPublicKey(c.Cfg.Identity, keys.TypeEncryption)
	if err != nil {
		return nil, fmt.Errorf("client: load encryption public key: %w", err)
	}
	return []RecipientCandidate{{Fingerprint: fp, PrivateKey: priv, PublicKey: pub}}, nil
}

// RecipientCandidate is a local alias used when building decryption candidates.
type RecipientCandidate struct {
	Fingerprint keys.Fingerprint
	PrivateKey  []byte
	PublicKey   []byte
}

// senderEncryptionPubKey returns the user's own encryption public key and
// fingerprint for self-encryption (sent-copy).
func (c *Client) senderEncryptionPubKey() ([]byte, keys.Fingerprint, error) {
	pub, fp, err := c.Store.LoadUserPublicKey(c.Cfg.Identity, keys.TypeEncryption)
	if err != nil {
		return nil, "", fmt.Errorf("client: load sender encryption pub key: %w", err)
	}
	if fp == "" {
		return nil, "", fmt.Errorf("client: no encryption key found for %s", c.Cfg.Identity)
	}
	return pub, fp, nil
}

// decodePubKey decodes a base64-encoded public key from a key record.
func decodePubKey(rec *keys.Record) ([]byte, error) {
	return base64.StdEncoding.DecodeString(rec.PublicKey)
}
