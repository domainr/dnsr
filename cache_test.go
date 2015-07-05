package dnsr

import (
	"testing"

	"github.com/nbio/st"
)

func TestCache(t *testing.T) {
	c := newCache(100)
	c.addNX("hello.")
	rr := RR{Name: "hello.", Type: "A", Value: "1.2.3.4"}
	c.add("hello.", rr)
	rrs := c.get("hello.")
	st.Expect(t, len(rrs), 1)
}
