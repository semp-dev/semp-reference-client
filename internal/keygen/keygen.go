// Package keygen generates identity and encryption key pairs for SEMP users.
package keygen

import (
	"fmt"
	"log/slog"

	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/keys"
	"semp.dev/semp-reference-client/internal/store"
)

// EnsureKeys generates identity (Ed25519) and encryption (KEM) key pairs
// for address if they do not already exist in the store.
func EnsureKeys(s *store.SQLiteStore, suite crypto.Suite, address string, logger *slog.Logger) error {
	has, err := s.HasUserKeys(address)
	if err != nil {
		return fmt.Errorf("keygen: check user keys %s: %w", address, err)
	}
	if has {
		logger.Info("user keys already exist", "address", address)
		return nil
	}

	// Identity key (Ed25519).
	idPub, idPriv, err := suite.Signer().GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("keygen: identity key for %s: %w", address, err)
	}
	idFP := s.PutUserKeyPair(address, keys.TypeIdentity, "ed25519", idPub, idPriv)

	// Encryption key (KEM).
	encPub, encPriv, err := suite.KEM().GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("keygen: encryption key for %s: %w", address, err)
	}
	encFP := s.PutUserKeyPair(address, keys.TypeEncryption, string(suite.ID()), encPub, encPriv)

	logger.Info("generated user keys",
		"address", address,
		"identity_fp", idFP,
		"encryption_fp", encFP)
	return nil
}
