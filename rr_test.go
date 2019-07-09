package dnsr

import (
	"testing"

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
