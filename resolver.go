package dnsr

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

// DNS Resolution configuration.
var (
	Timeout             = 2000 * time.Millisecond
	TypicalResponseTime = 100 * time.Millisecond
	MaxRecursion        = 10
	MaxNameservers      = 2
	MaxIPs              = 2
)

// Resolver errors.
var (
	NXDOMAIN = fmt.Errorf("NXDOMAIN")

	ErrMaxRecursion = fmt.Errorf("maximum recursion depth reached: %d", MaxRecursion)
	ErrMaxIPs       = fmt.Errorf("maximum name server IPs queried: %d", MaxIPs)
	ErrNoARecords   = fmt.Errorf("no A records found for name server")
	ErrNoResponse   = fmt.Errorf("no responses received")
	ErrTimeout      = fmt.Errorf("timeout expired") // TODO: Timeouter interface? e.g. func (e) Timeout() bool { return true }
)

// A ContextDialer implements the DialContext method, e.g. net.Dialer.
type ContextDialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// Option specifies a configuration option for a Resolver.
type Option func(*Resolver)

// WithCache specifies a cache with capacity cap.
func WithCache(cap int) Option {
	return func(r *Resolver) {
		r.capacity = cap
	}
}

// WithDialer specifies a network dialer.
func WithDialer(d ContextDialer) Option {
	return func(r *Resolver) {
		r.dialer = d
	}
}

// WithExpiry specifies that the Resolver will delete stale cache entries.
func WithExpiry() Option {
	return func(r *Resolver) {
		r.expire = true
	}
}

// WithTimeout specifies the timeout for network operations.
// The default value is Timeout.
func WithTimeout(timeout time.Duration) Option {
	return func(r *Resolver) {
		r.timeout = timeout
	}
}

// WithTCPRetry specifies that requests should be retried with TCP if responses
// are truncated. The retry must still complete within the timeout or context deadline.
func WithTCPRetry() Option {
	return func(r *Resolver) {
		r.tcpRetry = true
	}
}

// Resolver implements a primitive, non-recursive, caching DNS resolver.
type Resolver struct {
	dialer   ContextDialer
	timeout  time.Duration
	cache    *cache
	capacity int
	expire   bool
	tcpRetry bool
}

// NewResolver returns an initialized Resolver with options.
// By default, the returned Resolver will have cache capacity 0
// and the default network timeout (Timeout).
func NewResolver(options ...Option) *Resolver {
	r := &Resolver{timeout: Timeout}
	for _, o := range options {
		o(r)
	}
	r.cache = newCache(r.capacity, r.expire)
	return r
}

// New initializes a Resolver with the specified cache size.
// Deprecated: use NewResolver with Option(s) instead.
func New(cap int) *Resolver {
	return NewResolver(WithCache(cap))
}

// NewWithTimeout initializes a Resolver with the specified cache size and timeout.
// Deprecated: use NewResolver with Option(s) instead.
func NewWithTimeout(cap int, timeout time.Duration) *Resolver {
	return NewResolver(WithCache(cap), WithTimeout(timeout))
}

// NewExpiring initializes an expiring Resolver with the specified cache size.
// Deprecated: use NewResolver with Option(s) instead.
func NewExpiring(cap int) *Resolver {
	return NewResolver(WithCache(cap), WithExpiry())
}

// NewExpiringWithTimeout initializes an expiring Resolved with the specified cache size and timeout.
// Deprecated: use NewResolver with Option(s) instead.
func NewExpiringWithTimeout(cap int, timeout time.Duration) *Resolver {
	return NewResolver(WithCache(cap), WithTimeout(timeout), WithExpiry())
}

// Resolve calls ResolveErr to find DNS records of type qtype for the domain qname.
// For nonexistent domains (NXDOMAIN), it will return an empty, non-nil slice.
func (r *Resolver) Resolve(qname, qtype string) RRs {
	rrs, err := r.ResolveErr(qname, qtype)
	if err == NXDOMAIN {
		return emptyRRs
	}
	if err != nil {
		return nil
	}
	return rrs
}

// ResolveErr finds DNS records of type qtype for the domain qname.
// For nonexistent domains, it will return an NXDOMAIN error.
// Specify an empty string in qtype to receive any DNS records found
// (currently A, AAAA, NS, CNAME, SOA, and TXT).
func (r *Resolver) ResolveErr(qname, qtype string) (RRs, error) {
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()
	return r.resolve(ctx, toLowerFQDN(qname), qtype, 0)
}

// ResolveCtx finds DNS records of type qtype for the domain qname using
// the supplied context. Requests may time out earlier if timeout is
// shorter than a deadline set in ctx.
// For nonexistent domains, it will return an NXDOMAIN error.
// Specify an empty string in qtype to receive any DNS records found
// (currently A, AAAA, NS, CNAME, SOA, and TXT).
// Deprecated: use ResolveContext.
func (r *Resolver) ResolveCtx(ctx context.Context, qname, qtype string) (RRs, error) {
	return r.ResolveContext(ctx, qname, qtype)
}

// ResolveContext finds DNS records of type qtype for the domain qname using
// the supplied context. Requests may time out earlier if timeout is
// shorter than a deadline set in ctx.
// For nonexistent domains, it will return an NXDOMAIN error.
// Specify an empty string in qtype to receive any DNS records found
// (currently A, AAAA, NS, CNAME, SOA, and TXT).
func (r *Resolver) ResolveContext(ctx context.Context, qname, qtype string) (RRs, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	return r.resolve(ctx, toLowerFQDN(qname), qtype, 0)
}

func (r *Resolver) resolve(ctx context.Context, qname, qtype string, depth int) (RRs, error) {
	if depth++; depth > MaxRecursion {
		logMaxRecursion(qname, qtype, depth)
		return nil, ErrMaxRecursion
	}
	rrs, err := r.cacheGet(ctx, qname, qtype)
	if err != nil {
		return nil, err
	}
	if len(rrs) > 0 {
		return rrs, nil
	}
	logResolveStart(qname, qtype, depth)
	start := time.Now()
	rrs, err = r.iterateParents(ctx, qname, qtype, depth)
	logResolveEnd(qname, qtype, rrs, depth, start, err)
	return rrs, err
}

func (r *Resolver) iterateParents(ctx context.Context, qname, qtype string, depth int) (RRs, error) {
	chanRRs := make(chan RRs, MaxNameservers)
	chanErrs := make(chan error, MaxNameservers)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	for pname, ok := qname, true; ok; pname, ok = parent(pname) {
		// If we’re looking for [foo.com,NS], then move on to the parent ([com,NS])
		if pname == qname && qtype == "NS" {
			continue
		}

		// Only query TLDs against the root nameservers
		if pname == "." && dns.CountLabel(qname) != 1 {
			// fmt.Fprintf(os.Stderr, "Warning: non-TLD query at root: dig +norecurse %s %s\n", qname, qtype)
			return nil, nil
		}

		// Get nameservers
		nrrs, err := r.resolve(ctx, pname, "NS", depth)
		if err == NXDOMAIN || err == ErrTimeout || err == context.DeadlineExceeded {
			return nil, err
		}
		if err != nil {
			continue
		}

		// Check cache for specific queries
		if len(nrrs) > 0 && qtype != "" {
			rrs, err := r.cacheGet(ctx, qname, qtype)
			if err != nil {
				return nil, err
			}
			if len(rrs) > 0 {
				return rrs, nil
			}
		}

		// Query all nameservers in parallel
		count := 0
		for i := 0; i < len(nrrs) && count < MaxNameservers; i++ {
			nrr := nrrs[i]
			if nrr.Type != "NS" {
				continue
			}

			go func(host string) {
				rrs, err := r.exchange(ctx, host, qname, qtype, depth)
				if err != nil {
					chanErrs <- err
				} else {
					chanRRs <- rrs
				}
			}(nrr.Value)

			count++
		}

		// Wait for answer, error, or cancellation
		for ; count > 0; count-- {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case rrs := <-chanRRs:
				for _, nrr := range nrrs {
					if nrr.Name == qname {
						rrs = append(rrs, nrr)
					}
				}
				cancel() // stop any other work here before recursing
				return r.resolveCNAMEs(ctx, qname, qtype, rrs, depth)
			case err = <-chanErrs:
				if err == NXDOMAIN {
					return nil, err
				}
			}

		}

		// NS queries naturally recurse, so stop further iteration
		if qtype == "NS" {
			return nil, err
		}
	}

	return nil, ErrNoResponse
}

func (r *Resolver) exchange(ctx context.Context, host, qname, qtype string, depth int) (RRs, error) {
	count := 0
	arrs, err := r.resolve(ctx, host, "A", depth)
	if err != nil {
		return nil, err
	}
	for _, arr := range arrs {
		// FIXME: support AAAA records?
		if arr.Type != "A" {
			continue
		}

		// Never query more than MaxIPs for any nameserver
		if count++; count > MaxIPs {
			return nil, ErrMaxIPs
		}

		rrs, err := r.exchangeIP(ctx, host, arr.Value, qname, qtype, depth)
		if err == nil || err == NXDOMAIN || err == ErrTimeout {
			return rrs, err
		}

		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}

	return nil, ErrNoARecords
}

var dialerDefault = &net.Dialer{}

func (r *Resolver) exchangeIP(ctx context.Context, host, ip, qname, qtype string, depth int) (RRs, error) {
	dtype := dns.StringToType[qtype]
	if dtype == 0 {
		dtype = dns.TypeA
	}
	var qmsg dns.Msg
	qmsg.SetQuestion(qname, dtype)
	qmsg.MsgHdr.RecursionDesired = false

	// Synchronously query this DNS server
	start := time.Now()
	timeout := r.timeout // belt and suspenders, since ctx has a deadline from ResolveErr
	if dl, ok := ctx.Deadline(); ok {
		if start.After(dl.Add(-TypicalResponseTime)) { // bail if we can't finish in time (start is too close to deadline)
			return nil, ErrTimeout
		}
		timeout = dl.Sub(start)
	}

	// client must finish within remaining timeout
	client := &dns.Client{Timeout: timeout}

	dialer := r.dialer
	if dialer == nil {
		dialer = dialerDefault
	}

	addr := net.JoinHostPort(ip, "53")
	conn, err := dialer.DialContext(ctx, "udp", addr)
	var rmsg *dns.Msg
	var dur time.Duration
	if err == nil {
		dconn := &dns.Conn{Conn: conn}
		rmsg, dur, err = client.ExchangeWithConnContext(ctx, &qmsg, dconn)
		conn.Close()
	}
	if r.tcpRetry && rmsg != nil && rmsg.MsgHdr.Truncated {
		// Since we are doing another query, we need to recheck the deadline
		if dl, ok := ctx.Deadline(); ok {
			if start.After(dl.Add(-TypicalResponseTime)) { // bail if we can't finish in time (start is too close to deadline)
				return nil, ErrTimeout
			}
			client.Timeout = dl.Sub(start)
		}
		// Retry with TCP
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err == nil {
			dconn := &dns.Conn{Conn: conn}
			rmsg, dur, err = client.ExchangeWithConnContext(ctx, &qmsg, dconn)
			conn.Close()
		}
	}

	select {
	case <-ctx.Done(): // Finished too late
		logCancellation(host, &qmsg, rmsg, depth, dur, client.Timeout)
		return nil, ctx.Err()
	default:
		logExchange(host, &qmsg, rmsg, depth, dur, client.Timeout, err) // Log hostname instead of IP
	}
	if err != nil {
		return nil, err
	}

	// FIXME: cache NXDOMAIN responses responsibly
	if rmsg.Rcode == dns.RcodeNameError {
		var hasSOA bool
		if qtype == "NS" {
			for _, drr := range rmsg.Ns {
				rr, ok := convertRR(drr, r.expire)
				if !ok {
					continue
				}
				if rr.Type == "SOA" {
					hasSOA = true
					break
				}
			}
		}
		if !hasSOA {
			r.cache.addNX(qname)
			return nil, NXDOMAIN
		}
	} else if rmsg.Rcode != dns.RcodeSuccess {
		return nil, errors.New(dns.RcodeToString[rmsg.Rcode]) // FIXME: should (*Resolver).exchange special-case this error?
	}

	// Cache records returned
	rrs := r.saveDNSRR(host, qname, append(append(rmsg.Answer, rmsg.Ns...), rmsg.Extra...))

	// Resolve IP addresses of TLD name servers if NS query doesn’t return additional section
	if qtype == "NS" {
		for _, rr := range rrs {
			if rr.Type != "NS" {
				continue
			}
			arrs, err := r.cacheGet(ctx, rr.Value, "A")
			if err == NXDOMAIN {
				continue
			}
			if err != nil {
				break
			}
			if len(arrs) == 0 {
				arrs, err = r.exchangeIP(ctx, host, ip, rr.Value, "A", depth+1)
				if err != nil {
					break
				}
			}
			rrs = append(rrs, arrs...)
		}
	}

	return rrs, nil
}

func (r *Resolver) resolveCNAMEs(ctx context.Context, qname, qtype string, crrs RRs, depth int) (RRs, error) {
	var rrs RRs
	for _, crr := range crrs {
		rrs = append(rrs, crr)
		if crr.Type != "CNAME" || crr.Name != qname {
			continue
		}
		logCNAME(crr.String(), depth)
		crrs, _ := r.resolve(ctx, crr.Value, qtype, depth)
		for _, rr := range crrs {
			r.cache.add(qname, rr)
			rrs = append(rrs, crr)
		}
	}
	return rrs, nil
}

// saveDNSRR saves 1 or more DNS records to the resolver cache.
func (r *Resolver) saveDNSRR(host, qname string, drrs []dns.RR) RRs {
	var rrs RRs
	cl := dns.CountLabel(qname)
	for _, drr := range drrs {
		rr, ok := convertRR(drr, r.expire)
		if !ok {
			continue
		}
		if dns.CountLabel(rr.Name) < cl && dns.CompareDomainName(qname, rr.Name) < 2 {
			// fmt.Fprintf(os.Stderr, "Warning: potential poisoning from %s: %s -> %s\n", host, qname, drr.String())
			continue
		}
		r.cache.add(rr.Name, rr)
		if rr.Name != qname {
			continue
		}
		rrs = append(rrs, rr)
	}
	return rrs
}

// cacheGet returns a randomly ordered slice of DNS records.
func (r *Resolver) cacheGet(ctx context.Context, qname, qtype string) (RRs, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	any := r.cache.get(qname)
	if any == nil {
		any = rootCache.get(qname)
	}
	if any == nil {
		return nil, nil
	}
	if len(any) == 0 {
		return nil, NXDOMAIN
	}
	rrs := make(RRs, 0, len(any))
	for _, rr := range any {
		if qtype == "" || rr.Type == qtype {
			rrs = append(rrs, rr)
		}
	}
	if len(rrs) == 0 && (qtype != "" && qtype != "NS") {
		return nil, nil
	}
	return rrs, nil
}
