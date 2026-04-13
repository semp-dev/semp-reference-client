// Command semp-client is the SEMP reference client. It demonstrates the
// full client-side SEMP protocol: key registration, handshake, envelope
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
	"semp.dev/semp-reference-client/internal/store"
)

const usage = `semp-client — SEMP reference client

Usage:
  semp-client [flags] <command> [command-flags]

Commands:
  register    Generate keys and register with the home server
  send        Compose, encrypt, and submit an envelope
  fetch       Fetch and decrypt pending envelopes
  inbox       List received messages
  sent        List sent messages
  read        Display a decrypted message
  keys        Request recipient keys from the server
  export      Export a message as a .semp file
  import      Import and decrypt a .semp file
  status      Show identity, keys, and server info

Flags:
  -config string   Path to TOML config file (default "semp.toml")
`

func main() {
	configPath := flag.String("config", "semp.toml", "path to TOML config file")

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
	case "register":
		runRegister(ctx, cfg, s, logger, cmdArgs)
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

func runRegister(ctx context.Context, cfg *config.Config, s *store.SQLiteStore, logger *slog.Logger, args []string) {
	fs := flag.NewFlagSet("register", flag.ExitOnError)
	password := fs.String("password", "", "account password (required)")
	fs.Parse(args)

	if *password == "" {
		fmt.Fprintln(os.Stderr, "error: -password is required")
		fmt.Fprintln(os.Stderr, "usage: semp-client register -password <password>")
		os.Exit(1)
	}

	c := client.New(cfg, s, logger)
	if err := c.Register(ctx, *password); err != nil {
		logger.Error("registration failed", "err", err)
		os.Exit(1)
	}

	_, idFP, _ := s.LoadUserPrivateKey(cfg.Identity, keys.TypeIdentity)
	_, encFP, _ := s.LoadUserPrivateKey(cfg.Identity, keys.TypeEncryption)
	fmt.Printf("Registered: %s\n", cfg.Identity)
	fmt.Printf("Identity key:   %s\n", idFP)
	fmt.Printf("Encryption key: %s\n", encFP)
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

	_, idFP, _ := s.LoadUserPrivateKey(cfg.Identity, keys.TypeIdentity)
	_, encFP, _ := s.LoadUserPrivateKey(cfg.Identity, keys.TypeEncryption)
	if idFP != "" {
		fmt.Printf("Identity key:   %s\n", idFP)
	} else {
		fmt.Println("Identity key:   not registered (run 'register')")
	}
	if encFP != "" {
		fmt.Printf("Encryption key: %s\n", encFP)
	} else {
		fmt.Println("Encryption key: not registered (run 'register')")
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
