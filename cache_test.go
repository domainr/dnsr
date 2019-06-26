package dnsr

import (
	"testing"
	"time"

	"github.com/nbio/st"
)

func TestCache(t *testing.T) {
	c := newCache(100, false)
	c.addNX("hello.")
	rr := RR{Name: "hello.", Type: "A", Value: "1.2.3.4"}
	c.add("hello.", rr)
	rrs := c.get("hello.")
	st.Expect(t, len(rrs), 1)
}

func TestLiveCacheEntry(t *testing.T) {
	c := newCache(100, true)
	c.addNX("alive.")
	alive := time.Now().Add(time.Minute)
	rr := RR{Name: "alive.", Type: "A", Value: "1.2.3.4", Expiry: &alive}
	c.add("alive.", rr)
	rrs := c.get("alive.")
	st.Expect(t, len(rrs), 1)
}

func TestExpiredCacheEntry(t *testing.T) {
	c := newCache(100, true)
	c.addNX("expired.")
	expired := time.Now().Add(-time.Minute)
	rr := RR{Name: "expired.", Type: "A", Value: "1.2.3.4", Expiry: &expired}
	c.add("expired.", rr)
	rrs := c.get("expired.")
	st.Expect(t, len(rrs), 0)
}
