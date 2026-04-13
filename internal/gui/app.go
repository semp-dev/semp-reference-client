// Package gui provides a Fyne-based desktop GUI for the SEMP reference client.
package gui

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/data/binding"

	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/keys"

	"semp.dev/semp-reference-client/internal/client"
	"semp.dev/semp-reference-client/internal/config"
	"semp.dev/semp-reference-client/internal/store"
)

// GUIApp holds all shared state for the GUI application.
type GUIApp struct {
	App    fyne.App
	Window fyne.Window
	Cfg    *config.Config
	Store  *store.SQLiteStore
	Logger *slog.Logger

	// Live client connection (nil until first network operation).
	client   *client.Client
	clientMu sync.Mutex

	// Observable state for UI binding.
	ConnState    binding.String
	IdentityText binding.String
	IDKeyFP      binding.String
	EncKeyFP     binding.String

	// Current folder and messages.
	CurrentFolder string // "received" or "sent"
	messages      []store.Message
	messagesMu    sync.RWMutex

	// UI panels.
	sidebar       *Sidebar
	messageList   *MessageListPanel
	messageDetail *MessageDetailPanel
	statusBar     *StatusBar
}

// NewGUIApp creates a new GUI application with initial state.
func NewGUIApp(app fyne.App, window fyne.Window, cfg *config.Config, s *store.SQLiteStore, logger *slog.Logger) *GUIApp {
	g := &GUIApp{
		App:           app,
		Window:        window,
		Cfg:           cfg,
		Store:         s,
		Logger:        logger,
		ConnState:     binding.NewString(),
		IdentityText:  binding.NewString(),
		IDKeyFP:       binding.NewString(),
		EncKeyFP:      binding.NewString(),
		CurrentFolder: "received",
	}
	g.ConnState.Set("Disconnected")
	g.IdentityText.Set(cfg.Identity)
	g.loadKeyFingerprints()
	return g
}

// Build assembles the full GUI layout and sets it as the window content.
func (g *GUIApp) Build() {
	g.sidebar = NewSidebar(g)
	g.messageList = NewMessageListPanel(g)
	g.messageDetail = NewMessageDetailPanel(g)
	g.statusBar = NewStatusBar(g)

	content := BuildLayout(g)
	g.Window.SetContent(content)
	g.Window.SetMainMenu(BuildMenu(g))
	g.Window.Resize(fyne.NewSize(1000, 650))

	// Load initial messages.
	g.RefreshMessages()
}

// RefreshMessages reloads messages from the store for the current folder.
func (g *GUIApp) RefreshMessages() {
	msgs, err := g.Store.ListMessages(g.CurrentFolder)
	if err != nil {
		g.Logger.Error("failed to load messages", "err", err)
		return
	}
	g.messagesMu.Lock()
	g.messages = msgs
	g.messagesMu.Unlock()

	if g.messageList != nil {
		g.messageList.Refresh()
	}
}

// Messages returns a copy of the current message list.
func (g *GUIApp) Messages() []store.Message {
	g.messagesMu.RLock()
	defer g.messagesMu.RUnlock()
	out := make([]store.Message, len(g.messages))
	copy(out, g.messages)
	return out
}

// GetClient returns the active client, connecting if necessary.
// Thread-safe — only one connect/handshake runs at a time.
func (g *GUIApp) GetClient(ctx context.Context) (*client.Client, error) {
	g.clientMu.Lock()
	defer g.clientMu.Unlock()

	if g.client != nil {
		sess := g.client.Session()
		if sess != nil {
			return g.client, nil
		}
		// Session gone — close and reconnect.
		g.client.Close()
		g.client = nil
	}

	g.ConnState.Set("Connecting...")
	c := client.New(g.Cfg, g.Store, g.Logger)
	if err := c.ConnectAndHandshake(ctx); err != nil {
		g.ConnState.Set("Disconnected")
		return nil, fmt.Errorf("connect: %w", err)
	}
	c.AutoRekey(ctx)
	g.client = c
	g.ConnState.Set("Connected")
	return c, nil
}

// DisconnectClient tears down the active connection.
func (g *GUIApp) DisconnectClient() {
	g.clientMu.Lock()
	defer g.clientMu.Unlock()
	if g.client != nil {
		g.client.Close()
		g.client = nil
	}
	g.ConnState.Set("Disconnected")
}

// loadKeyFingerprints reads key fingerprints from the store and sets bindings.
func (g *GUIApp) loadKeyFingerprints() {
	_, idFP, _ := g.Store.LoadUserPrivateKey(g.Cfg.Identity, keys.TypeIdentity)
	_, encFP, _ := g.Store.LoadUserPrivateKey(g.Cfg.Identity, keys.TypeEncryption)
	if idFP != "" {
		g.IDKeyFP.Set(string(idFP))
	} else {
		g.IDKeyFP.Set("not generated")
	}
	if encFP != "" {
		g.EncKeyFP.Set(string(encFP))
	} else {
		g.EncKeyFP.Set("not generated")
	}
}

// Suite returns the crypto suite used by this client.
func (g *GUIApp) Suite() crypto.Suite {
	suite := crypto.LookupSuite(crypto.SuiteID(g.Cfg.Suite))
	if suite == nil {
		return crypto.SuitePQ
	}
	return suite
}
