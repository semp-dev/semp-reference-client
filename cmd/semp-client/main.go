// Command semp-client is the SEMP reference client. It demonstrates the
// full client-side SEMP protocol: key generation, handshake, envelope
// composition/encryption, submission, fetching/decryption, key requests,
// session rekeying, and .semp file import/export.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"time"

	"semp.dev/semp-go/brief"
	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/envelope"
	"semp.dev/semp-go/keys"

	"semp.dev/semp-reference-client/internal/client"
	"semp.dev/semp-reference-client/internal/config"
	"semp.dev/semp-reference-client/internal/keygen"
	"semp.dev/semp-reference-client/internal/store"
)

const usage = `semp-client — SEMP reference client

Usage:
  semp-client [flags] <command> [command-flags]

Commands:
  init          Generate identity and encryption keys
  import-keys   Import keys exported from the server (semp-server export-keys)
  send          Compose, encrypt, and submit an envelope
  fetch         Fetch and decrypt pending envelopes
  inbox         List received messages
  sent          List sent messages
  read          Display a decrypted message
  keys          Request recipient keys from the server
  export        Export a message as a .semp file
  import        Import and decrypt a .semp file
  status        Show identity, keys, and server info

Flags:
  -config string   Path to TOML config file (default "semp.toml")
`

func main() {
	configPath := flag.String("config", "semp.toml", "path to TOML config file")

	// Parse global flags before subcommand.
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		os.Exit(1)
	}
	cmd := args[0]
	cmdArgs := args[1:]

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("failed to load config", "err", err)
		os.Exit(1)
	}

	db, err := store.InitDB(cfg.Database.Path)
	if err != nil {
		logger.Error("failed to init database", "err", err)
		os.Exit(1)
	}
	defer db.Close()
	s := store.NewSQLiteStore(db)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	switch cmd {
	case "init":
		runInit(cfg, s, logger)
	case "import-keys":
		runImportKeys(cfg, s, logger, cmdArgs)
	case "send":
		runSend(ctx, cfg, s, logger, cmdArgs)
	case "fetch":
		runFetch(ctx, cfg, s, logger)
	case "inbox":
		runInbox(s)
	case "sent":
		runSent(s)
	case "read":
		runRead(s, cmdArgs)
	case "keys":
		runKeys(ctx, cfg, s, logger, cmdArgs)
	case "export":
		runExport(s, cmdArgs)
	case "import":
		runImport(cfg, s, logger, cmdArgs)
	case "status":
		runStatus(cfg, s)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		flag.Usage()
		os.Exit(1)
	}
}

// ---------------------------------------------------------------------------
// Subcommands
// ---------------------------------------------------------------------------

func runInit(cfg *config.Config, s *store.SQLiteStore, logger *slog.Logger) {
	suite := crypto.SuiteBaseline
	if err := keygen.EnsureKeys(s, suite, cfg.Identity, logger); err != nil {
		logger.Error("init failed", "err", err)
		os.Exit(1)
	}

	// Print key fingerprints.
	_, idFP, _ := s.LoadUserPrivateKey(cfg.Identity, keys.TypeIdentity)
	_, encFP, _ := s.LoadUserPrivateKey(cfg.Identity, keys.TypeEncryption)
	fmt.Printf("Identity:   %s\n", cfg.Identity)
	fmt.Printf("Domain:     %s\n", cfg.Domain)
	fmt.Printf("Identity key fingerprint:   %s\n", idFP)
	fmt.Printf("Encryption key fingerprint: %s\n", encFP)
}

// ExportedKeys matches the JSON format produced by semp-server export-keys.
type ExportedKeys struct {
	Address          string `json:"address"`
	Domain           string `json:"domain"`
	DomainSigningKey string `json:"domain_signing_key"`
	IdentityPub      string `json:"identity_public_key"`
	IdentityPriv     string `json:"identity_private_key"`
	IdentityFP       string `json:"identity_fingerprint"`
	EncryptionPub    string `json:"encryption_public_key"`
	EncryptionPriv   string `json:"encryption_private_key"`
	EncryptionFP     string `json:"encryption_fingerprint"`
	Algorithm        string `json:"algorithm"`
}

func runImportKeys(cfg *config.Config, s *store.SQLiteStore, logger *slog.Logger, args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: semp-client import-keys <keys.json>")
		fmt.Fprintln(os.Stderr, "\nImport keys exported from the server with: semp-server export-keys -address alice@example.com -o keys.json")
		os.Exit(1)
	}

	data, err := os.ReadFile(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading %s: %v\n", args[0], err)
		os.Exit(1)
	}

	var exported ExportedKeys
	if err := json.Unmarshal(data, &exported); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing keys file: %v\n", err)
		os.Exit(1)
	}

	if exported.Address != cfg.Identity {
		fmt.Fprintf(os.Stderr, "error: key file is for %s but config identity is %s\n", exported.Address, cfg.Identity)
		os.Exit(1)
	}

	idPub, err := base64.StdEncoding.DecodeString(exported.IdentityPub)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error decoding identity public key: %v\n", err)
		os.Exit(1)
	}
	idPriv, err := base64.StdEncoding.DecodeString(exported.IdentityPriv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error decoding identity private key: %v\n", err)
		os.Exit(1)
	}
	encPub, err := base64.StdEncoding.DecodeString(exported.EncryptionPub)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error decoding encryption public key: %v\n", err)
		os.Exit(1)
	}
	encPriv, err := base64.StdEncoding.DecodeString(exported.EncryptionPriv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error decoding encryption private key: %v\n", err)
		os.Exit(1)
	}

	idFP := s.PutUserKeyPair(exported.Address, keys.TypeIdentity, "ed25519", idPub, idPriv)
	encFP := s.PutUserKeyPair(exported.Address, keys.TypeEncryption, exported.Algorithm, encPub, encPriv)

	// Store the server's domain signing key so the client can verify
	// the server's handshake signature.
	if exported.DomainSigningKey != "" {
		domPub, err := base64.StdEncoding.DecodeString(exported.DomainSigningKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not decode domain signing key: %v\n", err)
		} else {
			domFP := s.PutDomainKeyPair(exported.Domain, "signing", "ed25519", domPub, nil)
			fmt.Printf("Domain signing key:         %s\n", domFP)
		}
	}

	fmt.Printf("Imported keys for %s\n", exported.Address)
	fmt.Printf("Identity key fingerprint:   %s\n", idFP)
	fmt.Printf("Encryption key fingerprint: %s\n", encFP)
}

func runSend(ctx context.Context, cfg *config.Config, s *store.SQLiteStore, logger *slog.Logger, args []string) {
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	to := fs.String("to", "", "recipient address (required)")
	cc := fs.String("cc", "", "CC addresses (comma-separated)")
	subject := fs.String("subject", "", "message subject")
	body := fs.String("body", "", "message body (text/plain)")
	attach := fs.String("attach", "", "file paths to attach (comma-separated)")
	fs.Parse(args)

	if *to == "" {
		fmt.Fprintln(os.Stderr, "error: -to is required")
		os.Exit(1)
	}

	opts := client.SendOptions{
		To:      strings.Split(*to, ","),
		Subject: *subject,
		Body:    *body,
	}
	if *cc != "" {
		opts.CC = strings.Split(*cc, ",")
	}
	if *attach != "" {
		opts.Attachments = strings.Split(*attach, ",")
	}

	c := client.New(cfg, s, logger)
	defer c.Close()

	if err := c.ConnectAndHandshake(ctx); err != nil {
		logger.Error("connect failed", "err", err)
		os.Exit(1)
	}

	resp, err := c.Send(ctx, opts)
	if err != nil {
		logger.Error("send failed", "err", err)
		os.Exit(1)
	}

	fmt.Printf("Envelope submitted: %s\n", resp.EnvelopeID)
	for _, r := range resp.Results {
		fmt.Printf("  %s: %s", r.Recipient, r.Status)
		if r.Reason != "" {
			fmt.Printf(" (%s)", r.Reason)
		}
		fmt.Println()
	}
}

func runFetch(ctx context.Context, cfg *config.Config, s *store.SQLiteStore, logger *slog.Logger) {
	c := client.New(cfg, s, logger)
	defer c.Close()

	if err := c.ConnectAndHandshake(ctx); err != nil {
		logger.Error("connect failed", "err", err)
		os.Exit(1)
	}

	messages, err := c.Fetch(ctx)
	if err != nil {
		logger.Error("fetch failed", "err", err)
		os.Exit(1)
	}

	if len(messages) == 0 {
		fmt.Println("No new messages.")
		return
	}

	for _, m := range messages {
		fmt.Printf("\n--- Message %s ---\n", m.MessageID)
		fmt.Printf("From:    %s\n", m.From)
		fmt.Printf("To:      %s\n", joinBriefAddrs(m.To))
		if len(m.CC) > 0 {
			fmt.Printf("CC:      %s\n", joinBriefAddrs(m.CC))
		}
		fmt.Printf("Subject: %s\n", m.Subject)
		fmt.Printf("Body:\n%s\n", m.Body)
		if len(m.Attachments) > 0 {
			fmt.Println("Attachments:")
			for _, a := range m.Attachments {
				fmt.Printf("  - %s (%s, %d bytes)\n", a.Filename, a.MimeType, a.Size)
			}
		}
	}
	fmt.Printf("\n%d message(s) fetched.\n", len(messages))
}

func runInbox(s *store.SQLiteStore) {
	msgs, err := s.ListMessages("received")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if len(msgs) == 0 {
		fmt.Println("Inbox is empty.")
		return
	}
	printMessageList(msgs)
}

func runSent(s *store.SQLiteStore) {
	msgs, err := s.ListMessages("sent")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if len(msgs) == 0 {
		fmt.Println("No sent messages.")
		return
	}
	printMessageList(msgs)
}

func runRead(s *store.SQLiteStore, args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: semp-client read <message-id>")
		os.Exit(1)
	}
	msgID := args[0]
	msg, err := s.GetMessage(msgID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if msg == nil {
		fmt.Fprintf(os.Stderr, "message not found: %s\n", msgID)
		os.Exit(1)
	}

	fmt.Printf("Message ID: %s\n", msg.MessageID)
	fmt.Printf("Direction:  %s\n", msg.Direction)
	fmt.Printf("From:       %s\n", msg.From)
	fmt.Printf("To:         %s\n", strings.Join(msg.To, ", "))
	if len(msg.CC) > 0 {
		fmt.Printf("CC:         %s\n", strings.Join(msg.CC, ", "))
	}
	fmt.Printf("Subject:    %s\n", msg.Subject)
	fmt.Printf("Date:       %s\n", msg.StoredAt)
	fmt.Printf("\n%s\n", msg.BodyText)
}

func runKeys(ctx context.Context, cfg *config.Config, s *store.SQLiteStore, logger *slog.Logger, args []string) {
	fs := flag.NewFlagSet("keys", flag.ExitOnError)
	address := fs.String("address", "", "address to look up (required)")
	fs.Parse(args)

	if *address == "" {
		fmt.Fprintln(os.Stderr, "error: -address is required")
		os.Exit(1)
	}

	c := client.New(cfg, s, logger)
	defer c.Close()

	if err := c.ConnectAndHandshake(ctx); err != nil {
		logger.Error("connect failed", "err", err)
		os.Exit(1)
	}

	fetcher := keys.NewFetcher(c.Conn())
	reqID := fmt.Sprintf("kr-%d", time.Now().UnixNano())
	req := keys.NewRequest(reqID, []string{*address})

	resp, err := fetcher.FetchKeys(ctx, req)
	if err != nil {
		logger.Error("key request failed", "err", err)
		os.Exit(1)
	}

	for _, r := range resp.Results {
		fmt.Printf("Address: %s  Status: %s  Domain: %s\n", r.Address, r.Status, r.Domain)
		if r.DomainKey != nil {
			fmt.Printf("  Domain signing key: %s (algo: %s, expires: %s)\n",
				r.DomainKey.KeyID, r.DomainKey.Algorithm, r.DomainKey.Expires.Format(time.RFC3339))
		}
		if r.DomainEncKey != nil {
			fmt.Printf("  Domain encryption key: %s (algo: %s, expires: %s)\n",
				r.DomainEncKey.KeyID, r.DomainEncKey.Algorithm, r.DomainEncKey.Expires.Format(time.RFC3339))
		}
		for _, uk := range r.UserKeys {
			fmt.Printf("  User key [%s]: %s (algo: %s, expires: %s)\n",
				uk.Type, uk.KeyID, uk.Algorithm, uk.Expires.Format(time.RFC3339))
			if uk.Revocation != nil {
				fmt.Printf("    REVOKED at %s: %s\n",
					uk.Revocation.RevokedAt.Format(time.RFC3339), uk.Revocation.Reason)
			}
		}
		if r.ErrorReason != "" {
			fmt.Printf("  Error: %s\n", r.ErrorReason)
		}
	}
}

func runExport(s *store.SQLiteStore, args []string) {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	output := fs.String("o", "", "output file path (default: <message-id>.semp)")
	fs.Parse(args)

	remaining := fs.Args()
	if len(remaining) == 0 {
		fmt.Fprintln(os.Stderr, "usage: semp-client export <message-id> [-o file.semp]")
		os.Exit(1)
	}
	msgID := remaining[0]

	msg, err := s.GetMessage(msgID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if msg == nil {
		fmt.Fprintf(os.Stderr, "message not found: %s\n", msgID)
		os.Exit(1)
	}
	if len(msg.RawEnvelope) == 0 {
		fmt.Fprintf(os.Stderr, "no raw envelope stored for message %s\n", msgID)
		os.Exit(1)
	}

	// Re-decode to get the envelope struct, then encode as file format.
	env, err := envelope.Decode(msg.RawEnvelope)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error decoding stored envelope: %v\n", err)
		os.Exit(1)
	}
	data, err := envelope.EncodeFile(env)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error encoding .semp file: %v\n", err)
		os.Exit(1)
	}

	outPath := *output
	if outPath == "" {
		outPath = msgID + ".semp"
	}
	if err := os.WriteFile(outPath, data, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "error writing %s: %v\n", outPath, err)
		os.Exit(1)
	}
	fmt.Printf("Exported to %s\n", outPath)
}

func runImport(cfg *config.Config, s *store.SQLiteStore, logger *slog.Logger, args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: semp-client import <file.semp>")
		os.Exit(1)
	}
	path := args[0]

	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading %s: %v\n", path, err)
		os.Exit(1)
	}

	env, err := envelope.DecodeFile(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error decoding .semp file: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Envelope ID:   %s\n", env.Postmark.ID)
	fmt.Printf("From domain:   %s\n", env.Postmark.FromDomain)
	fmt.Printf("To domain:     %s\n", env.Postmark.ToDomain)
	fmt.Printf("Session ID:    %s\n", env.Postmark.SessionID)
	fmt.Printf("Expires:       %s\n", env.Postmark.Expires.Format(time.RFC3339))
	fmt.Printf("Algorithm:     %s\n", env.Seal.Algorithm)

	// Try to verify signature if we have the domain key cached.
	suite := crypto.SuiteBaseline
	ctx := context.Background()
	domRec, _ := s.LookupDomainKey(ctx, env.Postmark.FromDomain)
	if domRec != nil {
		domPub, err := base64.StdEncoding.DecodeString(domRec.PublicKey)
		if err == nil {
			if err := envelope.VerifySignature(env, suite, domPub); err != nil {
				fmt.Printf("Signature:     INVALID (%v)\n", err)
			} else {
				fmt.Printf("Signature:     valid\n")
			}
		}
	} else {
		fmt.Printf("Signature:     not verified (domain key not cached)\n")
	}

	// Attempt decryption.
	priv, fp, err := s.LoadUserPrivateKey(cfg.Identity, keys.TypeEncryption)
	if err != nil || fp == "" {
		fmt.Println("\nCannot decrypt: no encryption key available.")
		return
	}
	candidates := []envelope.RecipientPrivateKey{
		{Fingerprint: fp, PrivateKey: priv},
	}

	b, err := envelope.OpenBriefAny(env, suite, candidates)
	if err != nil {
		fmt.Printf("\nBrief decryption failed: %v\n", err)
		return
	}
	enc, err := envelope.OpenEnclosureAny(env, suite, candidates)
	if err != nil {
		fmt.Printf("\nEnclosure decryption failed: %v\n", err)
		return
	}

	fmt.Printf("\n--- Decrypted Message ---\n")
	fmt.Printf("Message ID: %s\n", b.MessageID)
	fmt.Printf("From:       %s\n", b.From)
	fmt.Printf("To:         %s\n", joinBriefAddrs(b.To))
	if len(b.CC) > 0 {
		fmt.Printf("CC:         %s\n", joinBriefAddrs(b.CC))
	}
	fmt.Printf("Subject:    %s\n", enc.Subject)
	fmt.Printf("\n%s\n", enc.Body.Get("text/plain"))

	if len(enc.Attachments) > 0 {
		fmt.Println("Attachments:")
		for _, a := range enc.Attachments {
			fmt.Printf("  - %s (%s, %d bytes)\n", a.Filename, a.MimeType, a.Size)
		}
	}

	// Store imported message.
	rawJSON, _ := json.Marshal(env)
	toStrs := make([]string, len(b.To))
	for i, a := range b.To {
		toStrs[i] = string(a)
	}
	_ = s.StoreMessage(b.MessageID, "received", string(b.From),
		toStrs, nil, enc.Subject, enc.Body.Get("text/plain"), rawJSON)
}

func runStatus(cfg *config.Config, s *store.SQLiteStore) {
	fmt.Printf("Identity:   %s\n", cfg.Identity)
	fmt.Printf("Domain:     %s\n", cfg.Domain)
	fmt.Printf("Server:     %s\n", cfg.Server)
	fmt.Printf("Database:   %s\n", cfg.Database.Path)
	fmt.Printf("TLS:        insecure=%v\n", cfg.TLS.Insecure)

	_, idFP, _ := s.LoadUserPrivateKey(cfg.Identity, keys.TypeIdentity)
	_, encFP, _ := s.LoadUserPrivateKey(cfg.Identity, keys.TypeEncryption)
	if idFP != "" {
		fmt.Printf("Identity key:   %s\n", idFP)
	} else {
		fmt.Println("Identity key:   not generated (run 'init')")
	}
	if encFP != "" {
		fmt.Printf("Encryption key: %s\n", encFP)
	} else {
		fmt.Println("Encryption key: not generated (run 'init')")
	}

	inbox, _ := s.ListMessages("received")
	sent, _ := s.ListMessages("sent")
	fmt.Printf("Inbox:      %d message(s)\n", len(inbox))
	fmt.Printf("Sent:       %d message(s)\n", len(sent))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func printMessageList(msgs []store.Message) {
	fmt.Printf("%-36s  %-8s  %-25s  %s\n", "MESSAGE ID", "DIR", "FROM", "SUBJECT")
	fmt.Println(strings.Repeat("-", 100))
	for _, m := range msgs {
		subj := m.Subject
		if len(subj) > 40 {
			subj = subj[:37] + "..."
		}
		fmt.Printf("%-36s  %-8s  %-25s  %s\n", m.MessageID, m.Direction, m.From, subj)
	}
	fmt.Printf("\n%d message(s)\n", len(msgs))
}

func joinBriefAddrs(addrs []brief.Address) string {
	if len(addrs) == 0 {
		return ""
	}
	parts := make([]string, len(addrs))
	for i, a := range addrs {
		parts[i] = string(a)
	}
	return strings.Join(parts, ", ")
}
