package config

// ConnectionObservabilityConfig controls the upstream connection recorder
// (observability.connections in the v8 config).
type ConnectionObservabilityConfig struct {
	// Enabled turns recording on. Default: false.
	Enabled bool `yaml:"enabled" json:"enabled"`
	// HistorySize is the number of closed connections kept in memory. Default: 500.
	HistorySize int `yaml:"history-size,omitempty" json:"history-size,omitempty"`
	// RequestHistorySize is the number of upstream requests kept in memory. Default: 1000.
	RequestHistorySize int `yaml:"request-history-size,omitempty" json:"request-history-size,omitempty"`
}
