package store

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"time"

	"semp.dev/semp-go/keys"
)

// SQLiteStore implements keys.PrivateStore backed by SQLite. It also
// provides local message and contact storage for the reference client.
type SQLiteStore struct {
	db *sql.DB
}

// NewSQLiteStore wraps an initialised database.
func NewSQLiteStore(db *sql.DB) *SQLiteStore {
	return &SQLiteStore{db: db}
}

// DB returns the underlying database handle.
func (s *SQLiteStore) DB() *sql.DB { return s.db }

// ---------------------------------------------------------------------------
// keys.Store implementation
// ---------------------------------------------------------------------------

// LookupDomainKey returns the current signing key for domain.
func (s *SQLiteStore) LookupDomainKey(ctx context.Context, domain string) (*keys.Record, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT algorithm, public_key, key_id, created_at, expires_at,
		        revoked_at, revocation_reason, replacement_key_id
		   FROM domain_keys
		  WHERE domain = ? AND key_type = 'signing'`,
		domain)
	return scanDomainRow(row, domain)
}

// LookupDomainEncryptionKey returns the domain encryption key.
func (s *SQLiteStore) LookupDomainEncryptionKey(ctx context.Context, domain string) (*keys.Record, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT algorithm, public_key, key_id, created_at, expires_at,
		        revoked_at, revocation_reason, replacement_key_id
		   FROM domain_keys
		  WHERE domain = ? AND key_type = 'encryption'`,
		domain)
	return scanDomainRow(row, domain)
}

func scanDomainRow(row *sql.Row, domain string) (*keys.Record, error) {
	var (
		algorithm, keyID, createdStr, expiresStr string
		pubBytes                                 []byte
		revokedAt, revokeReason, replacementID   sql.NullString
	)
	err := row.Scan(&algorithm, &pubBytes, &keyID, &createdStr, &expiresStr,
		&revokedAt, &revokeReason, &replacementID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	created, _ := time.Parse(time.RFC3339, createdStr)
	expires, _ := time.Parse(time.RFC3339, expiresStr)
	rec := &keys.Record{
		Type:      keys.TypeDomain,
		Algorithm: algorithm,
		PublicKey: base64.StdEncoding.EncodeToString(pubBytes),
		KeyID:     keys.Fingerprint(keyID),
		Created:   created,
		Expires:   expires,
	}
	if revokedAt.Valid {
		revAt, _ := time.Parse(time.RFC3339, revokedAt.String)
		rec.Revocation = &keys.Revocation{
			Reason:           keys.Reason(revokeReason.String),
			RevokedAt:        revAt,
			ReplacementKeyID: keys.Fingerprint(replacementID.String),
		}
	}
	return rec, nil
}

// LookupUserKeys returns all current key records for address.
func (s *SQLiteStore) LookupUserKeys(ctx context.Context, address string, types ...keys.Type) ([]*keys.Record, error) {
	query := `SELECT key_type, algorithm, public_key, key_id, created_at, expires_at,
	                 revoked_at, revocation_reason, replacement_key_id
	            FROM user_keys WHERE address = ?`
	args := []any{address}
	if len(types) > 0 {
		placeholders := ""
		for i, t := range types {
			if i > 0 {
				placeholders += ","
			}
			placeholders += "?"
			args = append(args, string(t))
		}
		query += " AND key_type IN (" + placeholders + ")"
	}
	query += " AND revoked_at IS NULL"

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []*keys.Record
	for rows.Next() {
		var (
			keyType, algorithm, keyID, createdStr, expiresStr string
			pubBytes                                          []byte
			revokedAt, revokeReason, replacementID            sql.NullString
		)
		if err := rows.Scan(&keyType, &algorithm, &pubBytes, &keyID,
			&createdStr, &expiresStr, &revokedAt, &revokeReason, &replacementID); err != nil {
			return nil, err
		}
		created, _ := time.Parse(time.RFC3339, createdStr)
		expires, _ := time.Parse(time.RFC3339, expiresStr)
		rec := &keys.Record{
			Address:   address,
			Type:      keys.Type(keyType),
			Algorithm: algorithm,
			PublicKey: base64.StdEncoding.EncodeToString(pubBytes),
			KeyID:     keys.Fingerprint(keyID),
			Created:   created,
			Expires:   expires,
		}
		if revokedAt.Valid {
			revAt, _ := time.Parse(time.RFC3339, revokedAt.String)
			rec.Revocation = &keys.Revocation{
				Reason:           keys.Reason(revokeReason.String),
				RevokedAt:        revAt,
				ReplacementKeyID: keys.Fingerprint(replacementID.String),
			}
		}
		records = append(records, rec)
	}
	return records, rows.Err()
}

// PutRecord persists a user key record.
func (s *SQLiteStore) PutRecord(ctx context.Context, rec *keys.Record) error {
	if rec.Type == keys.TypeDomain {
		return nil // domain keys managed separately
	}
	pubBytes, err := base64.StdEncoding.DecodeString(rec.PublicKey)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO user_keys
		 (address, key_type, algorithm, public_key, key_id, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		rec.Address, string(rec.Type), rec.Algorithm, pubBytes,
		string(rec.KeyID), rec.Created.Format(time.RFC3339), rec.Expires.Format(time.RFC3339))
	return err
}

// PutRevocation records a key revocation.
func (s *SQLiteStore) PutRevocation(ctx context.Context, keyID keys.Fingerprint, rev *keys.Revocation) error {
	revokedAt := rev.RevokedAt.Format(time.RFC3339)
	reason := string(rev.Reason)
	replacement := string(rev.ReplacementKeyID)
	_, err := s.db.ExecContext(ctx,
		`UPDATE user_keys SET revoked_at = ?, revocation_reason = ?, replacement_key_id = ? WHERE key_id = ?`,
		revokedAt, reason, replacement, string(keyID))
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`UPDATE domain_keys SET revoked_at = ?, revocation_reason = ?, replacement_key_id = ? WHERE key_id = ?`,
		revokedAt, reason, replacement, string(keyID))
	return err
}

// LookupDeviceCertificate returns the device certificate for deviceKeyID.
func (s *SQLiteStore) LookupDeviceCertificate(ctx context.Context, deviceKeyID keys.Fingerprint) (*keys.DeviceCertificate, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT user_id, device_id, issuing_device_key_id, scope_json, issued_at, expires_at, signature_json
		   FROM device_certificates WHERE device_key_id = ?`,
		string(deviceKeyID))

	var (
		userID, deviceID, issuingKeyID, scopeJSON, issuedAtStr, sigJSON string
		expiresAt                                                       sql.NullString
	)
	err := row.Scan(&userID, &deviceID, &issuingKeyID, &scopeJSON, &issuedAtStr, &expiresAt, &sigJSON)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	cert := &keys.DeviceCertificate{
		UserID:             userID,
		DeviceID:           deviceID,
		DeviceKeyID:        deviceKeyID,
		IssuingDeviceKeyID: keys.Fingerprint(issuingKeyID),
	}
	cert.IssuedAt, _ = time.Parse(time.RFC3339, issuedAtStr)
	if expiresAt.Valid {
		cert.Expires, _ = time.Parse(time.RFC3339, expiresAt.String)
	}
	_ = json.Unmarshal([]byte(scopeJSON), &cert.Scope)
	_ = json.Unmarshal([]byte(sigJSON), &cert.Signature)
	return cert, nil
}

// PutDeviceCertificate stores a device certificate.
func (s *SQLiteStore) PutDeviceCertificate(ctx context.Context, cert *keys.DeviceCertificate) error {
	scopeJSON, _ := json.Marshal(cert.Scope)
	sigJSON, _ := json.Marshal(cert.Signature)
	expiresAt := ""
	if !cert.Expires.IsZero() {
		expiresAt = cert.Expires.Format(time.RFC3339)
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO device_certificates
		 (device_key_id, user_id, device_id, issuing_device_key_id, scope_json, issued_at, expires_at, signature_json)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		string(cert.DeviceKeyID), cert.UserID, cert.DeviceID,
		string(cert.IssuingDeviceKeyID), string(scopeJSON),
		cert.IssuedAt.Format(time.RFC3339), expiresAt, string(sigJSON))
	return err
}

// ---------------------------------------------------------------------------
// keys.PrivateStore implementation
// ---------------------------------------------------------------------------

// LoadPrivateKey returns the private key material for the given fingerprint.
func (s *SQLiteStore) LoadPrivateKey(_ context.Context, keyID keys.Fingerprint) ([]byte, error) {
	var priv []byte
	err := s.db.QueryRow(
		`SELECT private_key FROM user_keys WHERE key_id = ? AND private_key IS NOT NULL`,
		string(keyID)).Scan(&priv)
	if err == sql.ErrNoRows {
		// Try domain keys as well.
		err = s.db.QueryRow(
			`SELECT private_key FROM domain_keys WHERE key_id = ? AND private_key IS NOT NULL`,
			string(keyID)).Scan(&priv)
	}
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return priv, err
}

// StorePrivateKey writes private key material for the given fingerprint.
func (s *SQLiteStore) StorePrivateKey(_ context.Context, keyID keys.Fingerprint, priv []byte) error {
	res, err := s.db.Exec(
		`UPDATE user_keys SET private_key = ? WHERE key_id = ?`,
		priv, string(keyID))
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		_, err = s.db.Exec(
			`UPDATE domain_keys SET private_key = ? WHERE key_id = ?`,
			priv, string(keyID))
	}
	return err
}

// ---------------------------------------------------------------------------
// Server-specific helpers (shared with keygen)
// ---------------------------------------------------------------------------

// PutDomainKeyPair stores a domain key with its private key.
func (s *SQLiteStore) PutDomainKeyPair(domain, keyType, algorithm string, pub, priv []byte) keys.Fingerprint {
	fp := keys.Compute(pub)
	now := time.Now().UTC().Format(time.RFC3339)
	expires := time.Now().UTC().Add(2 * 365 * 24 * time.Hour).Format(time.RFC3339)
	_, _ = s.db.Exec(
		`INSERT OR REPLACE INTO domain_keys
		 (domain, key_type, algorithm, public_key, private_key, key_id, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		domain, keyType, algorithm, pub, priv, string(fp), now, expires)
	return fp
}

// PutUserKeyPair stores a user key with its private key.
func (s *SQLiteStore) PutUserKeyPair(address string, kt keys.Type, algorithm string, pub, priv []byte) keys.Fingerprint {
	fp := keys.Compute(pub)
	now := time.Now().UTC().Format(time.RFC3339)
	expires := time.Now().UTC().Add(365 * 24 * time.Hour).Format(time.RFC3339)
	_, _ = s.db.Exec(
		`INSERT OR REPLACE INTO user_keys
		 (address, key_type, algorithm, public_key, private_key, key_id, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		address, string(kt), algorithm, pub, priv, string(fp), now, expires)
	return fp
}

// HasUserKeys reports whether any keys exist for address.
func (s *SQLiteStore) HasUserKeys(address string) (bool, error) {
	var count int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM user_keys WHERE address = ?`, address).Scan(&count)
	return count > 0, err
}

// LoadUserPrivateKey retrieves a user's private key by address and type.
func (s *SQLiteStore) LoadUserPrivateKey(address string, kt keys.Type) ([]byte, keys.Fingerprint, error) {
	var priv []byte
	var keyID string
	err := s.db.QueryRow(
		`SELECT private_key, key_id FROM user_keys WHERE address = ? AND key_type = ? AND revoked_at IS NULL`,
		address, string(kt)).Scan(&priv, &keyID)
	if err == sql.ErrNoRows {
		return nil, "", nil
	}
	return priv, keys.Fingerprint(keyID), err
}

// LoadUserPublicKey retrieves a user's public key by address and type.
func (s *SQLiteStore) LoadUserPublicKey(address string, kt keys.Type) ([]byte, keys.Fingerprint, error) {
	var pub []byte
	var keyID string
	err := s.db.QueryRow(
		`SELECT public_key, key_id FROM user_keys WHERE address = ? AND key_type = ? AND revoked_at IS NULL`,
		address, string(kt)).Scan(&pub, &keyID)
	if err == sql.ErrNoRows {
		return nil, "", nil
	}
	return pub, keys.Fingerprint(keyID), err
}

// ---------------------------------------------------------------------------
// Message storage
// ---------------------------------------------------------------------------

// StoreMessage persists a decrypted message.
func (s *SQLiteStore) StoreMessage(msgID, direction, from string, to []string, cc []string, subject, bodyText string, rawEnvelope []byte) error {
	toJSON, _ := json.Marshal(to)
	ccJSON, _ := json.Marshal(cc)
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO messages
		 (message_id, direction, from_addr, to_addrs, cc_addrs, subject, body_text, raw_envelope, stored_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		msgID, direction, from, string(toJSON), string(ccJSON), subject, bodyText, rawEnvelope,
		time.Now().UTC().Format(time.RFC3339))
	return err
}

// Message represents a stored message.
type Message struct {
	MessageID   string
	Direction   string
	From        string
	To          []string
	CC          []string
	Subject     string
	BodyText    string
	RawEnvelope []byte
	StoredAt    string
}

// ListMessages returns messages filtered by direction.
func (s *SQLiteStore) ListMessages(direction string) ([]Message, error) {
	rows, err := s.db.Query(
		`SELECT message_id, direction, from_addr, to_addrs, cc_addrs, subject, body_text, raw_envelope, stored_at
		   FROM messages WHERE direction = ? ORDER BY stored_at DESC`,
		direction)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanMessages(rows)
}

// GetMessage returns a single message by ID.
func (s *SQLiteStore) GetMessage(messageID string) (*Message, error) {
	rows, err := s.db.Query(
		`SELECT message_id, direction, from_addr, to_addrs, cc_addrs, subject, body_text, raw_envelope, stored_at
		   FROM messages WHERE message_id = ?`,
		messageID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	msgs, err := scanMessages(rows)
	if err != nil {
		return nil, err
	}
	if len(msgs) == 0 {
		return nil, nil
	}
	return &msgs[0], nil
}

func scanMessages(rows *sql.Rows) ([]Message, error) {
	var msgs []Message
	for rows.Next() {
		var m Message
		var toJSON, ccJSON string
		var rawEnv []byte
		if err := rows.Scan(&m.MessageID, &m.Direction, &m.From, &toJSON, &ccJSON,
			&m.Subject, &m.BodyText, &rawEnv, &m.StoredAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(toJSON), &m.To)
		_ = json.Unmarshal([]byte(ccJSON), &m.CC)
		m.RawEnvelope = rawEnv
		msgs = append(msgs, m)
	}
	return msgs, rows.Err()
}

// ---------------------------------------------------------------------------
// Contact cache
// ---------------------------------------------------------------------------

// PutContact caches a recipient's encryption key.
func (s *SQLiteStore) PutContact(address, domain, encKeyID, encPubKey string) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO contacts (address, domain, enc_key_id, enc_pub_key, updated_at)
		 VALUES (?, ?, ?, ?, ?)`,
		address, domain, encKeyID, encPubKey, time.Now().UTC().Format(time.RFC3339))
	return err
}

// Contact represents a cached recipient.
type Contact struct {
	Address   string
	Domain    string
	EncKeyID  string
	EncPubKey string
}

// GetContact returns cached key info for a recipient.
func (s *SQLiteStore) GetContact(address string) (*Contact, error) {
	var c Contact
	err := s.db.QueryRow(
		`SELECT address, domain, enc_key_id, enc_pub_key FROM contacts WHERE address = ?`,
		address).Scan(&c.Address, &c.Domain, &c.EncKeyID, &c.EncPubKey)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &c, err
}
