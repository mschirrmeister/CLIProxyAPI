package management

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/connstats"
)

// GetConnections returns upstream connection metadata (observability.connections).
// The optional since query parameter (unix milliseconds) drops closed
// connections and finished requests that ended before it.
func (h *Handler) GetConnections(c *gin.Context) {
	var since time.Time
	if raw := strings.TrimSpace(c.Query("since")); raw != "" {
		ms, errParse := strconv.ParseInt(raw, 10, 64)
		if errParse != nil || ms < 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "since must be unix milliseconds"})
			return
		}
		since = time.UnixMilli(ms)
	}
	c.JSON(http.StatusOK, connstats.SnapshotSince(since))
}
