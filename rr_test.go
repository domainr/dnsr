package dnsr

import (
	"testing"
	"time"

	"github.com/nbio/st"
)

func TestRRStringStandard(t *testing.T) {
	rr := RR{
		Name:  "example.com.",
		Type:  "A",
		Value: "203.0.113.1",
	}
	result := rr.String()
	st.Expect(t, result, "example.com.	      3600	IN	A	203.0.113.1")
}

func TestRRStringExpiring(t *testing.T) {
	ttl := 86400 * time.Second
	rr := RR{
		Name:   "example.com.",
		Type:   "A",
		Value:  "203.0.113.1",
		TTL:    ttl,
		Expiry: time.Now().Add(ttl),
	}
	result := rr.String()
	st.Expect(t, result, "example.com.	     86400	IN	A	203.0.113.1")
}
