package dnsr

import (
	"flag"
	"os"
	"testing"

	"github.com/nbio/st"
)

var testResolver *Resolver

func init() {
	flag.Parse()
	if testing.Verbose() {
		DebugLogger = os.Stderr
	}
	testResolver = New(0)
	testResolve()
}

func TestSimple(t *testing.T) {
	r := New(0)
	accum(r.Resolve("1.com", ""))
}

func TestCache(t *testing.T) {
	r := New(5)
	st.Expect(t, r.cache.Len(), 0)
	accum(r.Resolve("1.com", ""))
	accum(r.Resolve("2.com", ""))
	accum(r.Resolve("3.com", ""))
	accum(r.Resolve("4.com", ""))
	accum(r.Resolve("5.com", ""))
	st.Expect(t, r.cache.Len(), 5)
	_ = r.Resolve("6.com", "")
	st.Expect(t, r.cache.Len(), 5)
}

func TestGoogleA(t *testing.T) {
	r := New(0)
	rrs := accum(r.Resolve("google.com", "A"))
	st.Expect(t, len(rrs) >= 10, true)
	st.Expect(t, count(rrs, func(rr *RR) bool { return rr.Type == "NS" }) >= 2, true)
	st.Expect(t, count(rrs, func(rr *RR) bool { return rr.Type == "A" }) >= 4, true)
}

func TestGoogleAny(t *testing.T) {
	r := New(0)
	rrs := accum(r.Resolve("google.com", ""))
	st.Expect(t, len(rrs) >= 10, true)
	st.Expect(t, count(rrs, func(rr *RR) bool { return rr.Type == "NS" }) >= 2, true)
	st.Expect(t, count(rrs, func(rr *RR) bool { return rr.Type == "A" }) >= 4, true)
}

func TestGoogleMulti(t *testing.T) {
	r := New(0)
	accum(r.Resolve("google.com", "A"))
	rrs := accum(r.Resolve("google.com", "TXT"))
	st.Expect(t, len(rrs) >= 10, true)
	st.Expect(t, count(rrs, func(rr *RR) bool { return rr.Type == "TXT" }), 1)
	st.Expect(t, count(rrs, func(rr *RR) bool { return rr.Type == "A" }) >= 4, true)
}

func TestGoogleTXT(t *testing.T) {
	r := New(0)
	rrs := accum(r.Resolve("google.com", "TXT"))
	st.Expect(t, len(rrs), 5)
	st.Expect(t, count(rrs, func(rr *RR) bool { return rr.Type == "TXT" }), 1)
}

func TestHerokuA(t *testing.T) {
	r := New(0)
	rrs := accum(r.Resolve("us-east-1-a.route.herokuapp.com", "A"))
	st.Expect(t, count(rrs, func(rr *RR) bool { return rr.Type == "A" }) >= 1, true)
}

func TestHerokuTXT(t *testing.T) {
	r := New(0)
	rrs := accum(r.Resolve("us-east-1-a.route.herokuapp.com", "TXT"))
	st.Expect(t, count(rrs, func(rr *RR) bool { return rr.Type == "TXT" }), 0)
}

func TestHerokuMulti(t *testing.T) {
	r := New(0)
	accum(r.Resolve("us-east-1-a.route.herokuapp.com", "A"))
	rrs := accum(r.Resolve("us-east-1-a.route.herokuapp.com", "TXT"))
	st.Expect(t, count(rrs, func(rr *RR) bool { return rr.Type == "TXT" }), 0)
	st.Expect(t, count(rrs, func(rr *RR) bool { return rr.Type == "A" }) >= 1, true)
}

func TestBlueOvenA(t *testing.T) {
	r := New(0)
	rrs := accum(r.Resolve("blueoven.com", "A"))
	st.Expect(t, len(rrs), 2)
	st.Expect(t, all(rrs, func(rr *RR) bool { return rr.Type == "NS" }), true)
}

func TestBlueOvenAny(t *testing.T) {
	r := New(0)
	rrs := accum(r.Resolve("blueoven.com", ""))
	st.Expect(t, len(rrs), 2)
	st.Expect(t, all(rrs, func(rr *RR) bool { return rr.Type == "NS" }), true)
}

func TestBlueOvenMulti(t *testing.T) {
	r := New(0)
	accum(r.Resolve("blueoven.com", "A"))
	accum(r.Resolve("blueoven.com", "TXT"))
	rrs := accum(r.Resolve("blueoven.com", ""))
	st.Expect(t, len(rrs), 2)
	st.Expect(t, all(rrs, func(rr *RR) bool { return rr.Type == "NS" }), true)
}

func TestBazCoUKAny(t *testing.T) {
	r := New(0)
	rrs := accum(r.Resolve("baz.co.uk", ""))
	st.Expect(t, len(rrs) >= 2, true)
	st.Expect(t, count(rrs, func(rr *RR) bool { return rr.Type == "NS" }) >= 2, true)
}

func BenchmarkResolve(b *testing.B) {
	for i := 0; i < b.N; i++ {
		testResolve()
	}
}

func testResolve() {
	accum(testResolver.Resolve("google.com", ""))
	accum(testResolver.Resolve("blueoven.com", ""))
	accum(testResolver.Resolve("baz.co.uk", ""))
	accum(testResolver.Resolve("us-east-1-a.route.herokuapp.com", ""))
}

func accum(in []*RR) []*RR {
	return in
}

func count(rrs []*RR, f func(*RR) bool) (out int) {
	for _, rr := range rrs {
		if f(rr) {
			out++
		}
	}
	return
}

func sum(rrs []*RR, f func(*RR) int) (out int) {
	for _, rr := range rrs {
		out += f(rr)
	}
	return
}

func all(rrs []*RR, f func(*RR) bool) (out bool) {
	for _, rr := range rrs {
		if !f(rr) {
			return false
		}
	}
	return true
}
