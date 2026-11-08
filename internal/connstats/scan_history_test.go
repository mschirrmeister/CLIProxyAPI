package connstats

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
	"time"
)

// containsMarker only tries newline positions, which is complete only while
// every marker starts with a newline.
func TestFinalEventMarkersStartWithNewline(t *testing.T) {
	for _, m := range finalEventMarkers {
		if len(m) < 2 || m[0] != '\n' || (m[1] != 'd' && m[1] != 'e') {
			t.Errorf("marker %q must start with a newline and then d or e", m)
		}
	}
}

func TestContainsMarkerMatchesSubstringSearch(t *testing.T) {
	naive := func(data []byte) bool {
		for _, m := range finalEventMarkers {
			if bytes.Contains(data, m) {
				return true
			}
		}
		return false
	}
	for _, s := range []string{
		"",
		"\n",
		"data: [DONE]",
		"\ndata: [DONE]",
		"x\ndata: [DONE]\n\n",
		"\n\ndata: [DON",
		"data: {\"text\":\"\\ndata: [DONE]\"}\n",
		"event: content_block_delta\n\nevent: message_stop\n",
		"\nevent: response.complete",
		"\nevent: response.completed",
		"\ndata: {\"type\":\"message_stop\"}",
		strings.Repeat("data: {}\n\n", 50) + "event: response.failed\n",
		strings.Repeat("\n", 40),
	} {
		if got, want := containsMarker([]byte(s)), naive([]byte(s)); got != want {
			t.Errorf("containsMarker(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestHistorySnapshotStaysAtLimit(t *testing.T) {
	enable(t)
	Configure(true, 0, 8, "")
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/v1", nil)
	for i := 1; i <= 40; i++ {
		rec := col.startRequest("p", "a", req)
		col.finishRequest(rec, EndEOF, nil)
		snap := SnapshotSince(time.Time{})
		want := min(i, 8)
		if len(snap.Requests) != want {
			t.Fatalf("after %d requests: snapshot has %d, want %d", i, len(snap.Requests), want)
		}
		if last := snap.Requests[len(snap.Requests)-1]; last.ID != rec.info.ID {
			t.Fatalf("after %d requests: newest is #%d, want #%d", i, last.ID, rec.info.ID)
		}
		col.mu.Lock()
		kept := len(col.requests)
		col.mu.Unlock()
		if kept > 8+historySlack(8) {
			t.Fatalf("after %d requests: %d kept, want at most %d", i, kept, 8+historySlack(8))
		}
	}
}
