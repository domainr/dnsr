package dnsr

import (
	"testing"

	"github.com/nbio/st"
)

func TestToLowerFQDN(t *testing.T) {
	st.Expect(t, toLowerFQDN("ANYTHING.com"), "anything.com.")
	st.Expect(t, toLowerFQDN("boO.net"), "boo.net.")
	st.Expect(t, toLowerFQDN("just.another.HORSE"), "just.another.horse.")
}
