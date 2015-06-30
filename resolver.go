package dnsr

import (
	"fmt"
	"time"

	"github.com/miekg/dns"
)

var (
	Timeout        = 2000 * time.Millisecond
	MaxRecursion   = 10
	MaxNameservers = 2
	MaxIPs         = 2

	NXDOMAIN        = fmt.Errorf("NXDOMAIN")
	ErrMaxRecursion = fmt.Errorf("maximum recursion depth reached: %d", MaxRecursion)
	ErrMaxIPs       = fmt.Errorf("maximum name server IPs queried: %d", MaxIPs)
	ErrNoARecords   = fmt.Errorf("no A records found for name server")
	ErrNoResponse   = fmt.Errorf("no responses received")
)

// Resolver implements a primitive, non-recursive, caching DNS resolver.
type Resolver struct {
	cache  *cache
	client *dns.Client
}

// New initializes a Resolver with the specified cache size.
func New(capacity int) *Resolver {
	r := &Resolver{
		cache: newCache(capacity),
		client: &dns.Client{
			DialTimeout:  Timeout,
			ReadTimeout:  Timeout,
			WriteTimeout: Timeout,
		},
	}
	return r
}

// Resolve finds DNS records of type qtype for the domain qname.
// For nonexistent domains (NXDOMAIN), it will return an empty, non-nil slice.
// Specify an empty string in qtype to receive any DNS records found
// (currently A, AAAA, NS, CNAME, and TXT).
func (r *Resolver) Resolve(qname string, qtype string) []*RR {
	rrs, err := r.resolve(qname, qtype, 0)
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
// (currently A, AAAA, NS, CNAME, and TXT).
func (r *Resolver) ResolveErr(qname string, qtype string) ([]*RR, error) {
	return r.resolve(qname, qtype, 0)
}

func (r *Resolver) resolve(qname string, qtype string, depth int) ([]*RR, error) {
	if depth++; depth > MaxRecursion {
		logMaxRecursion(qname, qtype, depth)
		return nil, ErrMaxRecursion
	}
	qname = toLowerFQDN(qname)
	rrs, err := r.cacheGet(qname, qtype)
	if err != nil {
		return nil, err
	}
	if len(rrs) > 0 {
		return rrs, nil
	}
	logResolveStart(qname, qtype, depth)
	rrs, err = r.iterateParents(qname, qtype, depth)
	logResolveEnd(qname, qtype, rrs, depth, time.Now(), err)
	return rrs, err
}

func (r *Resolver) iterateParents(qname string, qtype string, depth int) ([]*RR, error) {
	errs := make(chan error, MaxNameservers)
	for pname, ok := qname, true; ok; pname, ok = parent(pname) {
		if pname == qname && qtype == "NS" { // If we’re looking for [foo.com,NS], then skip to [com,NS]
			continue
		}

		// Only query TLDs against the root nameservers
		if pname == "." && dns.CountLabel(qname) != 1 {
			// fmt.Fprintf(os.Stderr, "Warning: non-TLD query at root: dig +norecurse %s %s\n", qname, qtype)
			return nil, nil
		}

		// Get nameservers
		nrrs, err := r.resolve(pname, "NS", depth)
		if err == NXDOMAIN {
			return nil, err
		}
		if err != nil {
			continue
		}

		// Early out for specific queries
		if len(nrrs) > 0 && qtype != "" {
			rrs, err := r.cacheGet(qname, qtype)
			if err != nil {
				return nil, err
			}
			if len(rrs) > 0 {
				return rrs, nil
			}
		}

		// Query all nameservers in parallel
		count := 0
		for _, nrr := range nrrs {
			if nrr.Type != "NS" {
				continue
			}

			go func(nrr *RR) {
				errs <- r.exchange(nrr.Value, qname, qtype, depth)
			}(nrr)

			count++
			if count >= MaxNameservers {
				break
			}
		}

		// Wait for first response
		for ; count > 0; count-- {
			select {
			case err = <-errs:
				if err == NXDOMAIN {
					return nil, err
				}
				if err == nil {
					return r.resolveCNAMEs(qname, qtype, depth)
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

func (r *Resolver) exchange(host string, qname string, qtype string, depth int) error {
	dtype := dns.StringToType[qtype]
	if dtype == 0 {
		dtype = dns.TypeA
	}
	qmsg := &dns.Msg{}
	qmsg.SetQuestion(qname, dtype)
	qmsg.MsgHdr.RecursionDesired = false

	// Find each A record for the DNS server
	count := 0
	rrs, err := r.resolve(host, "A", depth)
	if err != nil {
		return err
	}
	for _, rr := range rrs {
		if rr.Type != "A" { // FIXME: support AAAA records?
			continue
		}

		// Never query more than MaxIPs for any nameserver
		if count++; count > MaxIPs {
			return ErrMaxIPs
		}

		// Synchronously query this DNS server
		start := time.Now()
		rmsg, _, err := r.client.Exchange(qmsg, rr.Value+":53")
		logExchange(host, qmsg, depth, start, err) // Log hostname instead of IP
		if err != nil {
			continue
		}

		// FIXME: cache NXDOMAIN responses responsibly
		if rmsg.Rcode == dns.RcodeNameError {
			r.cache.add(qname, nil)
			return NXDOMAIN
		}

		// Cache records returned
		r.saveDNSRR(host, qname, append(append(rmsg.Answer, rmsg.Ns...), rmsg.Extra...)...)

		// Return after first successful network request
		return nil
	}

	return ErrNoARecords
}

func (r *Resolver) resolveCNAMEs(qname string, qtype string, depth int) ([]*RR, error) {
	crrs, err := r.cacheGet(qname, "")
	if err != nil {
		return nil, err
	}
	var rrs []*RR
	for _, crr := range crrs {
		rrs = append(rrs, crr)
		if crr.Type != "CNAME" {
			continue
		}
		logCNAME(crr.String(), depth)
		crrs, _ := r.resolve(crr.Value, qtype, depth)
		for _, rr := range crrs {
			r.cache.add(qname, rr)
			rrs = append(rrs, crr)
		}
	}
	return rrs, nil
}

// saveDNSRR saves 1 or more DNS records to the resolver cache.
func (r *Resolver) saveDNSRR(host string, qname string, drrs ...dns.RR) {
	cl := dns.CountLabel(qname)
	for _, drr := range drrs {
		if rr := convertRR(drr); rr != nil {
			if dns.CountLabel(rr.Name) < cl && dns.CompareDomainName(qname, rr.Name) < 2 {
				// fmt.Fprintf(os.Stderr, "Warning: potential poisoning from %s: %s -> %s\n", host, qname, drr.String())
				continue
			}
			r.cache.add(rr.Name, rr)
		}
	}
}

// cacheGet returns a randomly ordered slice of DNS records.
func (r *Resolver) cacheGet(qname string, qtype string) ([]*RR, error) {
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
	rrs := make([]*RR, 0, len(any))
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
