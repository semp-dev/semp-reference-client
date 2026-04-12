package client

import (
	"context"
	"time"

	"semp.dev/semp-go/session"
)

// AutoRekey starts a background goroutine that rekeys the session at 80%
// of its TTL. The goroutine exits when ctx is cancelled or the rekey fails.
func (c *Client) AutoRekey(ctx context.Context) {
	if c.session == nil {
		return
	}
	go c.autoRekey(ctx)
}

func (c *Client) autoRekey(ctx context.Context) {
	threshold := time.Duration(float64(c.session.TTL) * session.RekeyThreshold)
	timer := time.NewTimer(threshold)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return
	case <-timer.C:
	}

	if !c.session.Active(time.Now()) {
		c.Log.Warn("session expired before rekey")
		return
	}

	rekeyer := &session.Rekeyer{
		Suite:   c.Suite,
		Session: c.session,
	}
	if err := rekeyer.Rekey(ctx, c.conn); err != nil {
		c.Log.Warn("rekey failed", "err", err)
		return
	}
	c.Log.Info("session rekeyed",
		"new_session_id", c.session.ID,
		"expires_at", c.session.ExpiresAt)
}
