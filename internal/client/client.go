// Package client provides the core SEMP client: connection, handshake,
// session lifecycle, sending, receiving, and rekeying.
package client

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"

	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/handshake"
	"semp.dev/semp-go/keys"
	"semp.dev/semp-go/session"
	"semp.dev/semp-go/transport"
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
	return &Client{
		Cfg:   cfg,
		Store: s,
		Suite: crypto.SuiteBaseline,
		Log:   log,
	}
}

// Connect opens a WebSocket connection to the home server.
func (c *Client) Connect(ctx context.Context) error {
	// Load user key fingerprints from store.
	_, idFP, err := c.Store.LoadUserPrivateKey(c.Cfg.Identity, keys.TypeIdentity)
	if err != nil {
		return fmt.Errorf("client: load identity key: %w", err)
	}
	if idFP == "" {
		return fmt.Errorf("client: no identity key found for %s — run 'init' first", c.Cfg.Identity)
	}
	c.identityFP = idFP

	_, encFP, err := c.Store.LoadUserPrivateKey(c.Cfg.Identity, keys.TypeEncryption)
	if err != nil {
		return fmt.Errorf("client: load encryption key: %w", err)
	}
	c.encryptionFP = encFP

	// Dial WebSocket.
	t := ws.NewWithConfig(ws.Config{
		AllowInsecure: c.Cfg.TLS.Insecure,
	})
	conn, err := t.Dial(ctx, c.Cfg.Server)
	if err != nil {
		return fmt.Errorf("client: dial %s: %w", c.Cfg.Server, err)
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
	return []RecipientCandidate{{Fingerprint: fp, PrivateKey: priv}}, nil
}

// RecipientCandidate is a local alias used when building decryption candidates.
type RecipientCandidate struct {
	Fingerprint keys.Fingerprint
	PrivateKey  []byte
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
