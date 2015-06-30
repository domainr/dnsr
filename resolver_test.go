package dnsr

import (
	"flag"
	"fmt"
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
	_, err := r.ResolveErr("1.com", "")
	st.Expect(t, err, NXDOMAIN)
}

func TestCache(t *testing.T) {
	r := New(0)
	r.cache.capacity = 10
	st.Expect(t, len(r.cache.entries), 0)
	for i := 0; i < 10; i++ {
		r.Resolve(fmt.Sprintf("%d.com", i), "")
	}
	st.Expect(t, len(r.cache.entries), 10)
	_, err := r.ResolveErr("a.com", "")
	st.Expect(t, err, NXDOMAIN)
	st.Expect(t, len(r.cache.entries), 10)
}

func TestGoogleA(t *testing.T) {
	r := New(0)
	rrs, err := r.ResolveErr("google.com", "A")
	st.Expect(t, err, nil)
	st.Expect(t, len(rrs) >= 4, true)
	st.Expect(t, count(rrs, func(rr *RR) bool { return rr.Type == "NS" }) >= 2, true)
	st.Expect(t, count(rrs, func(rr *RR) bool { return rr.Type == "A" }) >= 1, true)
}

func TestGoogleAny(t *testing.T) {
	r := New(0)
	rrs, err := r.ResolveErr("google.com", "")
	st.Expect(t, err, nil)
	st.Expect(t, len(rrs) >= 4, true)
	st.Expect(t, count(rrs, func(rr *RR) bool { return rr.Type == "NS" }) >= 2, true)
	st.Expect(t, count(rrs, func(rr *RR) bool { return rr.Type == "A" }) >= 1, true)
}

func TestGoogleMulti(t *testing.T) {
	r := New(0)
	_, err := r.ResolveErr("google.com", "A")
	st.Expect(t, err, nil)
	rrs, err := r.ResolveErr("google.com", "TXT")
	st.Expect(t, err, nil)
	st.Expect(t, len(rrs) >= 5, true)
	st.Expect(t, count(rrs, func(rr *RR) bool { return rr.Type == "TXT" }), 1)
	st.Expect(t, count(rrs, func(rr *RR) bool { return rr.Type == "A" }) >= 1, true)
}

func TestGoogleTXT(t *testing.T) {
	r := New(0)
	rrs, err := r.ResolveErr("google.com", "TXT")
	st.Expect(t, err, nil)
	st.Expect(t, len(rrs), 5)
	st.Expect(t, count(rrs, func(rr *RR) bool { return rr.Type == "TXT" }), 1)
}

func TestHerokuA(t *testing.T) {
	r := New(0)
	rrs, err := r.ResolveErr("us-east-1-a.route.herokuapp.com", "A")
	st.Expect(t, err, nil)
	st.Expect(t, count(rrs, func(rr *RR) bool { return rr.Type == "A" }) >= 1, true)
}

func TestHerokuTXT(t *testing.T) {
	r := New(0)
	rrs, err := r.ResolveErr("us-east-1-a.route.herokuapp.com", "TXT")
	st.Expect(t, err, nil)
	st.Expect(t, count(rrs, func(rr *RR) bool { return rr.Type == "TXT" }), 0)
}

func TestHerokuMulti(t *testing.T) {
	r := New(0)
	_, err := r.ResolveErr("us-east-1-a.route.herokuapp.com", "A")
	st.Expect(t, err, nil)
	rrs, err := r.ResolveErr("us-east-1-a.route.herokuapp.com", "TXT")
	st.Expect(t, err, nil)
	st.Expect(t, count(rrs, func(rr *RR) bool { return rr.Type == "TXT" }), 0)
	st.Expect(t, count(rrs, func(rr *RR) bool { return rr.Type == "A" }) >= 1, true)
}

func TestBlueOvenA(t *testing.T) {
	r := New(0)
	rrs, err := r.ResolveErr("blueoven.com", "A")
	st.Expect(t, err, nil)
	st.Expect(t, len(rrs), 2)
	st.Expect(t, all(rrs, func(rr *RR) bool { return rr.Type == "NS" }), true)
}

func TestBlueOvenAny(t *testing.T) {
	r := New(0)
	rrs, err := r.ResolveErr("blueoven.com", "")
	st.Expect(t, err, nil)
	st.Expect(t, len(rrs), 2)
	st.Expect(t, all(rrs, func(rr *RR) bool { return rr.Type == "NS" }), true)
}

func TestBlueOvenMulti(t *testing.T) {
	r := New(0)
	_, err := r.ResolveErr("blueoven.com", "A")
	st.Expect(t, err, nil)
	_, err = r.ResolveErr("blueoven.com", "TXT")
	st.Expect(t, err, nil)
	rrs, err := r.ResolveErr("blueoven.com", "")
	st.Expect(t, err, nil)
	st.Expect(t, len(rrs), 2)
	st.Expect(t, all(rrs, func(rr *RR) bool { return rr.Type == "NS" }), true)
}

func TestBazCoUKAny(t *testing.T) {
	r := New(0)
	rrs, err := r.ResolveErr("baz.co.uk", "")
	st.Expect(t, err, nil)
	st.Expect(t, len(rrs) >= 2, true)
	st.Expect(t, count(rrs, func(rr *RR) bool { return rr.Type == "NS" }) >= 2, true)
}

func BenchmarkResolve(b *testing.B) {
	for i := 0; i < b.N; i++ {
		testResolve()
	}
}

func BenchmarkResolveErr(b *testing.B) {
	for i := 0; i < b.N; i++ {
		testResolveErr()
	}
}

func testResolve() {
	testResolver.Resolve("google.com", "")
	testResolver.Resolve("blueoven.com", "")
	testResolver.Resolve("baz.co.uk", "")
	testResolver.Resolve("us-east-1-a.route.herokuapp.com", "")
}

func testResolveErr() {
	testResolver.ResolveErr("google.com", "")
	testResolver.ResolveErr("blueoven.com", "")
	testResolver.ResolveErr("baz.co.uk", "")
	testResolver.ResolveErr("us-east-1-a.route.herokuapp.com", "")
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
