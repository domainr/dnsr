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

func TestWithCache(t *testing.T) {
	r := NewResolver(WithCache(99))
	st.Expect(t, r.cache.capacity, 99)
}

func TestWithDialer(t *testing.T) {
	d := &net.Dialer{}
	r := NewResolver(WithDialer(d))
	st.Expect(t, r.dialer, d)
}

func TestWithExpiry(t *testing.T) {
	r := NewResolver(WithExpiry())
	st.Expect(t, r.expire, true)
}

func TestWithTimeout(t *testing.T) {
	r := NewResolver(WithTimeout(99 * time.Second))
	st.Expect(t, r.timeout, 99*time.Second)
}

func TestNewExpiring(t *testing.T) {
	r := NewExpiring(42)
	st.Expect(t, r.cache.capacity, 42)
	st.Expect(t, r.expire, true)
}

func TestNewExpiringWithTimeout(t *testing.T) {
	r := NewExpiringWithTimeout(42, 99*time.Second)
	st.Expect(t, r.cache.capacity, 42)
	st.Expect(t, r.timeout, 99*time.Second)
	st.Expect(t, r.expire, true)
}

func TestNewExpiry(t *testing.T) {
	r := NewResolver(WithExpiry())
	st.Expect(t, r.expire, true)
}

func TestSimple(t *testing.T) {
	r := NewResolver()
	_, err := r.ResolveErr("1.com", "")
	st.Expect(t, err, NXDOMAIN)
}

func TestTimeoutExpiration(t *testing.T) {
	r := NewResolver(WithTimeout(10 * time.Millisecond))
	_, err := r.ResolveErr("1.com", "")
	st.Expect(t, err, ErrTimeout)
}

func TestDeadlineExceeded(t *testing.T) {
	r := NewResolver(WithTimeout(0))
	_, err := r.ResolveErr("1.com", "")
	st.Expect(t, err, context.DeadlineExceeded)
}

func TestResolveCtx(t *testing.T) {
	r := NewResolver()
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	_, err := r.ResolveCtx(ctx, "1.com", "")
	st.Expect(t, err, NXDOMAIN)
	cancel()
	_, err = r.ResolveCtx(ctx, "1.com", "")
	st.Expect(t, err, context.Canceled)
}

func TestResolveContext(t *testing.T) {
	r := NewResolver()
	ctx, cancel := context.WithCancel(context.Background())
	_, err := r.ResolveContext(ctx, "1.com", "")
	st.Expect(t, err, NXDOMAIN)
	cancel()
	_, err = r.ResolveContext(ctx, "1.com", "")
	st.Expect(t, err, context.Canceled)
}

func TestResolverCache(t *testing.T) {
	r := NewResolver()
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
	r := NewResolver()
	rrs, err := r.ResolveErr("google.com", "A")
	st.Expect(t, err, nil)
	st.Expect(t, len(rrs) >= 4, true)
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "NS" }) >= 2, true)
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "A" }) >= 1, true)
}

func TestGooglePTR(t *testing.T) {
	r := NewResolver()
	rrs, err := r.ResolveErr("99.17.217.172.in-addr.arpa", "PTR")
	st.Expect(t, err, nil)
	st.Expect(t, len(rrs) >= 2, true)
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "PTR" }) >= 1, true)
}

func TestGoogleMX(t *testing.T) {
	r := NewResolver()
	rrs, err := r.ResolveErr("google.com", "MX")
	st.Expect(t, err, nil)
	st.Expect(t, len(rrs) >= 4, true)
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "NS" }) >= 2, true)
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "MX" }) >= 1, true)
}

func TestGoogleAny(t *testing.T) {
	time.Sleep(Timeout) // To address flaky test on GitHub Actions
	r := NewResolver()
	rrs, err := r.ResolveErr("google.com", "")
	st.Expect(t, err, nil)
	st.Expect(t, len(rrs) >= 1, true)
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "NS" }) >= 2, true)
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "A" }) >= 1, true)
}

func TestGoogleMulti(t *testing.T) {
	r := NewResolver()
	_, err := r.ResolveErr("google.com", "A")
	st.Expect(t, err, nil)
	rrs, err := r.ResolveErr("google.com", "TXT")
	st.Expect(t, err, nil)
	st.Expect(t, len(rrs) >= 1, true)
	// Google will have at least an SPF record, but might transiently have verification records too.
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "TXT" }) >= 1, true)
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "A" }), 0)
}

func TestGoogleCNAME(t *testing.T) {
	r := NewResolver()
	rrs, err := r.ResolveErr("www.github.com", "A")
	st.Expect(t, err, nil)
	st.Expect(t, len(rrs) >= 1, true)
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "CNAME" }) >= 1, true) // resolved first
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "A" }) >= 1, true) // records for CNAME target
}

func TestGoogleTXT(t *testing.T) {
	checkTXT(t, "google.com")
}

func TestCloudflareTXT(t *testing.T) {
	checkTXT(t, "cloudflare.com")
}

func TestGoogleTXTTCPRetry(t *testing.T) {
	r := NewResolver()
	rrs, err := r.ResolveErr("google.com", "TXT")
	st.Expect(t, err, nil)
	st.Expect(t, len(rrs) >= 4, true)

	r2 := NewResolver(WithTCPRetry())
	rrs2, err := r2.ResolveErr("google.com", "TXT")
	st.Expect(t, err, nil)
	st.Expect(t, len(rrs2) > len(rrs), true)
}

func TestAppleA(t *testing.T) {
	r := NewResolver()
	rrs, err := r.ResolveErr("apple.com", "A")
	st.Expect(t, err, nil)
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "A" }) >= 1, true)
}

func TestHerokuTXT(t *testing.T) {
	r := NewResolver()
	rrs, err := r.ResolveErr("us-east-1-a.route.herokuapp.com", "TXT")
	st.Expect(t, err, nil)
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "TXT" }), 0)
}

func TestHerokuMulti(t *testing.T) {
	r := NewResolver()
	_, err := r.ResolveErr("us-east-1-a.route.herokuapp.com", "A")
	st.Expect(t, err, nil)
	rrs, err := r.ResolveErr("us-east-1-a.route.herokuapp.com", "TXT")
	st.Expect(t, err, nil)
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "TXT" }), 0)
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "A" }), 0)
}

func TestBlueOvenA(t *testing.T) {
	t.Skip("DNS changed 2018-11, so disabling this.")
	r := NewResolver()
	rrs, err := r.ResolveErr("blueoven.com", "A")
	st.Expect(t, err, nil)
	st.Expect(t, len(rrs), 2)
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "NS" && rr.Name == "blueoven.com." }), 2)
}

func TestBlueOvenAny(t *testing.T) {
	t.Skip("DNS changed 2018-11, so disabling this.")
	r := NewResolver()
	rrs, err := r.ResolveErr("blueoven.com", "")
	st.Expect(t, err, nil)
	st.Expect(t, len(rrs), 2)
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "NS" && rr.Name == "blueoven.com." }), 2)
}

func TestBlueOvenMulti(t *testing.T) {
	t.Skip("DNS changed 2018-11, so disabling this.")
	r := NewResolver()
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
	r := NewResolver()
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
	st.Expect(t, rr.Expiry.IsZero(), false)
}

func checkTXT(t *testing.T, domain string) {
	r := NewResolver(WithTCPRetry())
	rrs, err := r.ResolveErr(domain, "TXT")
	st.Expect(t, err, nil)

	rrs2, err := net.LookupTXT(domain)
	st.Expect(t, err, nil)
	for _, rr := range rrs2 {
		exists := false
		for _, rr2 := range rrs {
			if rr2.Type == "TXT" && rr == rr2.Value {
				exists = true
			}
		}
		if !exists {
			t.Errorf("TXT record %q not found", rr)
		}
	}
	c := count(rrs, func(rr RR) bool { return rr.Type == "TXT" })
	if c != len(rrs2) {
		t.Errorf("TXT record count mismatch: %d != %d", c, len(rrs2))
	}
}

var testResolver *Resolver

func BenchmarkResolve(b *testing.B) {
	testResolver = NewResolver()
	for i := 0; i < b.N; i++ {
		testResolve()
	}
}

func BenchmarkResolveErr(b *testing.B) {
	testResolver = NewResolver()
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

// BenchmarkResolveOOB benchmarks resolution of domains with out-of-bailiwick nameservers.
func BenchmarkResolveOOB(b *testing.B) {
	testResolver = NewResolver()
	for i := 0; i < b.N; i++ {
		testResolver.ResolveErr("pnnl.gov", "A")
	}
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

// TestOOB tests out-of-bailiwick (OOB) nameserver resolution.
// pnnl.gov uses nameservers in .net (adns1.es.net, adns2.es.net),
// which .gov nameservers cannot provide glue records for.
// See https://github.com/domainr/dnsr/issues/174
func TestOOB(t *testing.T) {
	r := NewResolver()
	rrs, err := r.ResolveErr("pnnl.gov", "A")
	st.Expect(t, err, nil)
	st.Expect(t, len(rrs) >= 3, true)
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "NS" }) >= 2, true)
	st.Expect(t, count(rrs, func(rr RR) bool { return rr.Type == "A" }) >= 1, true)
}

// TestOOBOtherDomains tests other domains from issue #174.
func TestOOBOtherDomains(t *testing.T) {
	r := NewResolver()
	for _, domain := range []string{"lbl.gov", "nrel.gov"} {
		rrs, err := r.ResolveErr(domain, "A")
		if err != nil {
			t.Errorf("%s: %v", domain, err)
			continue
		}
		if len(rrs) == 0 {
			t.Errorf("%s: no records returned", domain)
		}
	}
}
