package api

import (
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/connstats"
)

// applyConnectionObservabilityConfig applies observability.connections; reason
// marks the timeline ("startup", "config_reload").
func applyConnectionObservabilityConfig(cfg *config.Config, reason string) {
	if cfg == nil {
		return
	}
	c := cfg.ConnectionObservability
	connstats.Configure(c.Enabled, c.HistorySize, c.RequestHistorySize, reason)
}
