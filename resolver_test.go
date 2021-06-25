package dnsr

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/nbio/st"
)

func TestMain(m *testing.M) {
	flag.Parse()
	timeout := os.Getenv("DNSR_TIMEOUT")
	if timeout != "" {
		Timeout, _ = time.ParseDuration(timeout)
	}
	if os.Getenv("DNSR_DEBUG") != "" {
		DebugLogger = os.Stderr
	}
	os.Exit(m.Run())
}

func TestSimple(t *testing.T) {
	r := New(0)
	_, err := r.ResolveErr("1.com", "")
	st.Expect(t, err, NXDOMAIN)
}

func TestSimpleFuncOptions(t *testing.T) {
	r, _ := NewResolver(WithCapacity(0))
	_, err := r.ResolveErr("1.com", "")
	st.Expect(t, err, NXDOMAIN)
}

func TestTimeoutExpiration(t *testing.T) {
	r := NewWithTimeout(0, 10*time.Millisecond)
	_, err := r.ResolveErr("1.com", "")
	st.Expect(t, err, ErrTimeout)
}

func TestTimeoutExpirationFuncOptions(t *testing.T) {
	r, _ := NewResolver(WithTimeout(10 * time.Millisecond))
	_, err := r.ResolveErr("1.com", "")
	st.Expect(t, err, ErrTimeout)
}

func TestDeadlineExceeded(t *testing.T) {
	r := NewWithTimeout(0, 0)
	_, err := r.ResolveErr("1.com", "")
	st.Expect(t, err, context.DeadlineExceeded)
}

func TestDeadlineExceededFuncOptions(t *testing.T) {
	r, _ := NewResolver(WithTimeout(0))
	_, err := r.ResolveErr("1.com", "")
	st.Expect(t, err, context.DeadlineExceeded)
}

func TestDialer(t *testing.T) {
	r, _ := NewResolver(WithDialer(&net.Dialer{
		// iterative resolving from 127.0.0.1 should never work
		LocalAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 65353},
	}))
	res, err := r.ResolveErr("google.com", "A")
	// TODO: this causes a "connect: invalid argument" error inside the exchange method
	// however that error is not propagate upwards so we expect an empty RRs and no error.
	st.Expect(t, err, nil)
	st.Expect(t, len(res), 0)
}

func TestResolveCtx(t *testing.T) {
	r := New(0)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	_, err := r.ResolveCtx(ctx, "1.com", "")
	st.Expect(t, err, NXDOMAIN)
	cancel()
	_, err = r.ResolveCtx(ctx, "1.com", "")
	st.Expect(t, err, context.Canceled)
}

func TestResolverCache(t *testing.T) {
	r := New(0)
	r.cache.capacity = 10
	r.cache.m.Lock()
	st.Expect(t, len(r.cache.entries), 0)
	r.cache.m.Unlock()
	for i := 0; i < 10; i++ {
		r.Resolve(fmt.Sprintf("%d.com", i), "")
	}
	r.cache.m.Lock()
	st.Expect(t, len(r.cache.entries), 10)
	r.cache.m.Unlock()
	rrs, err := r.ResolveErr("a.com", "")
	st.Expect(t, err, NXDOMAIN)
	st.Expect(t, rrs, (RRs)(nil))
	r.cache.m.Lock()
	st.Expect(t, r.cache.entries["a.com"], entry(nil))
	st.Expect(t, len(r.cache.entries), 10)
	r.cache.m.Unlock()
}

func TestGoogleA(t *testing.T) {
	r := New(0)
	rrs, err := r.ResolveErr("google.com", "A")
	st.Expect(t, err, nil)
	st.Expect(t, len(rrs) >= 4, true)
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "NS" }) >= 2, true)
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "A" }) >= 1, true)
}

func TestGooglePTR(t *testing.T) {
	r := New(0)
	rrs, err := r.ResolveErr("99.17.217.172.in-addr.arpa", "PTR")
	st.Expect(t, err, nil)
	st.Expect(t, len(rrs) >= 2, true)
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "PTR" }) >= 1, true)
}

func TestGoogleMX(t *testing.T) {
	r := New(0)
	rrs, err := r.ResolveErr("google.com", "MX")
	st.Expect(t, err, nil)
	st.Expect(t, len(rrs) >= 4, true)
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "NS" }) >= 2, true)
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "MX" }) >= 2, true)
}

func TestGoogleAny(t *testing.T) {
	time.Sleep(Timeout) // To address flaky test on GitHub Actions
	r := New(0)
	rrs, err := r.ResolveErr("google.com", "")
	st.Expect(t, err, nil)
	st.Expect(t, len(rrs) >= 1, true)
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "NS" }) >= 2, true)
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "A" }) >= 1, true)
}

func TestGoogleMulti(t *testing.T) {
	r := New(0)
	_, err := r.ResolveErr("google.com", "A")
	st.Expect(t, err, nil)
	rrs, err := r.ResolveErr("google.com", "TXT")
	st.Expect(t, err, nil)
	st.Expect(t, len(rrs) >= 1, true)
	// Google will have at least an SPF record, but might transiently have verification records too.
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "TXT" }) >= 1, true)
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "A" }), 0)
}

func TestGoogleTXT(t *testing.T) {
	r := New(0)
	rrs, err := r.ResolveErr("google.com", "TXT")
	st.Expect(t, err, nil)
	st.Expect(t, len(rrs) >= 4, true)
	// Google will have at least an SPF record, but might transiently have verification records too.
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "TXT" }) >= 1, true)
}

func TestHerokuA(t *testing.T) {
	r := New(0)
	rrs, err := r.ResolveErr("us-east-1-a.route.herokuapp.com", "A")
	st.Expect(t, err, nil)
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "A" }) >= 1, true)
}

func TestHerokuTXT(t *testing.T) {
	r := New(0)
	rrs, err := r.ResolveErr("us-east-1-a.route.herokuapp.com", "TXT")
	st.Expect(t, err, nil)
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "TXT" }), 0)
}

func TestHerokuMulti(t *testing.T) {
	r := New(0)
	_, err := r.ResolveErr("us-east-1-a.route.herokuapp.com", "A")
	st.Expect(t, err, nil)
	rrs, err := r.ResolveErr("us-east-1-a.route.herokuapp.com", "TXT")
	st.Expect(t, err, nil)
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "TXT" }), 0)
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "A" }), 0)
}

func TestBlueOvenA(t *testing.T) {
	t.Skip("DNS changed 2018-11, so disabling this.")
	r := New(0)
	rrs, err := r.ResolveErr("blueoven.com", "A")
	st.Expect(t, err, nil)
	st.Expect(t, len(rrs), 2)
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "NS" && rr.Name == "blueoven.com." }), 2)
}

func TestBlueOvenAny(t *testing.T) {
	t.Skip("DNS changed 2018-11, so disabling this.")
	r := New(0)
	rrs, err := r.ResolveErr("blueoven.com", "")
	st.Expect(t, err, nil)
	st.Expect(t, len(rrs), 2)
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "NS" && rr.Name == "blueoven.com." }), 2)
}

func TestBlueOvenMulti(t *testing.T) {
	t.Skip("DNS changed 2018-11, so disabling this.")
	r := New(0)
	_, err := r.ResolveErr("blueoven.com", "A")
	st.Expect(t, err, nil)
	_, err = r.ResolveErr("blueoven.com", "TXT")
	st.Expect(t, err, nil)
	rrs, err := r.ResolveErr("blueoven.com", "")
	st.Expect(t, err, nil)
	st.Expect(t, len(rrs), 2)
	st.Expect(t, all(rrs, func(rr RR) bool { return rr.Type == "NS" }), true)
}

func TestBazCoUKAny(t *testing.T) {
	time.Sleep(Timeout) // To address flaky test on GitHub Actions
	r := New(0)
	rrs, err := r.ResolveErr("baz.co.uk", "")
	st.Expect(t, err, nil)
	st.Expect(t, len(rrs) >= 2, true)
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "NS" }) >= 2, true)
}

func TestTTL(t *testing.T) {
	r := NewExpiring(0)
	rrs, err := r.ResolveErr("google.com", "A")
	st.Expect(t, err, nil)
	st.Assert(t, len(rrs) >= 4, true)
	rr := rrs[0]
	st.Expect(t, !rr.Expiry.IsZero(), true)
}

func TestTTLFuncOptions(t *testing.T) {
	r, _ := NewResolver(Expiring())
	rrs, err := r.ResolveErr("google.com", "A")
	st.Expect(t, err, nil)
	st.Assert(t, len(rrs) >= 4, true)
	rr := rrs[0]
	st.Expect(t, !rr.Expiry.IsZero(), true)
}

var testResolver *Resolver

func BenchmarkResolve(b *testing.B) {
	testResolver = New(0)
	for i := 0; i < b.N; i++ {
		testResolve()
	}
}

func BenchmarkResolveErr(b *testing.B) {
	testResolver = New(0)
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

func count(rrs RRs, f func(RR) bool) (out int) {
	for _, rr := range rrs {
		if f(rr) {
			out++
		}
	}
	return
}

func sum(rrs RRs, f func(RR) int) (out int) {
	for _, rr := range rrs {
		out += f(rr)
	}
	return
}

func all(rrs RRs, f func(RR) bool) (out bool) {
	for _, rr := range rrs {
		if !f(rr) {
			return false
		}
	}
	return true
}
