package dnsr

import (
	"errors"
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
// (currently A, AAAA, NS, CNAME, SOA, and TXT).
func (r *Resolver) Resolve(qname string, qtype string) RRs {
	rrs, err := r.resolve(toLowerFQDN(qname), qtype, 0)
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
func (r *Resolver) ResolveErr(qname string, qtype string) (RRs, error) {
	return r.resolve(toLowerFQDN(qname), qtype, 0)
}

func (r *Resolver) resolve(qname string, qtype string, depth int) (RRs, error) {
	if depth++; depth > MaxRecursion {
		logMaxRecursion(qname, qtype, depth)
		return nil, ErrMaxRecursion
	}
	rrs, err := r.cacheGet(qname, qtype)
	if err != nil {
		return nil, err
	}
	if len(rrs) > 0 {
		return rrs, nil
	}
	logResolveStart(qname, qtype, depth)
	start := time.Now()
	rrs, err = r.iterateParents(qname, qtype, depth)
	logResolveEnd(qname, qtype, rrs, depth, start, err)
	return rrs, err
}

func (r *Resolver) iterateParents(qname string, qtype string, depth int) (RRs, error) {
	chanRRs := make(chan RRs, MaxNameservers)
	chanErrs := make(chan error, MaxNameservers)
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

			go func(host string) {
				rrs, err := r.exchange(host, qname, qtype, depth)
				if err != nil {
					chanErrs <- err
				} else {
					chanRRs <- rrs
				}
			}(nrr.Value)

			count++
			if count >= MaxNameservers {
				break
			}
		}

		// Wait for first response
		for ; count > 0; count-- {
			select {
			case rrs := <-chanRRs:
				for _, nrr := range nrrs {
					if nrr.Name == qname {
						rrs = append(rrs, nrr)
					}
				}
				return r.resolveCNAMEs(qname, qtype, rrs, depth)
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

func (r *Resolver) exchange(host string, qname string, qtype string, depth int) (RRs, error) {
	dtype := dns.StringToType[qtype]
	if dtype == 0 {
		dtype = dns.TypeA
	}
	qmsg := &dns.Msg{}
	qmsg.SetQuestion(qname, dtype)
	qmsg.MsgHdr.RecursionDesired = false

	// Find each A record for the DNS server
	count := 0
	arrs, err := r.resolve(host, "A", depth)
	if err != nil {
		return nil, err
	}
	for _, arr := range arrs {
		if arr.Type != "A" { // FIXME: support AAAA records?
			continue
		}

		// Never query more than MaxIPs for any nameserver
		if count++; count > MaxIPs {
			return nil, ErrMaxIPs
		}

		// Synchronously query this DNS server
		start := time.Now()
		rmsg, _, err := r.client.Exchange(qmsg, arr.Value+":53")
		logExchange(host, qmsg, rmsg, depth, start, err) // Log hostname instead of IP
		if err != nil {
			continue
		}

		// FIXME: cache NXDOMAIN responses responsibly
		if rmsg.Rcode == dns.RcodeNameError {
			var hasSOA bool
			if qtype == "NS" {
				for _, drr := range rmsg.Ns {
					rr, ok := convertRR(drr)
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
			return nil, errors.New(dns.RcodeToString[rmsg.Rcode])
		}

		// Cache records returned
		rrs := r.saveDNSRR(host, qname, append(append(rmsg.Answer, rmsg.Ns...), rmsg.Extra...))

		// Return after first successful network request
		return rrs, nil
	}

	return nil, ErrNoARecords
}

func (r *Resolver) resolveCNAMEs(qname string, qtype string, crrs RRs, depth int) (RRs, error) {
	var rrs RRs
	for _, crr := range crrs {
		rrs = append(rrs, crr)
		if crr.Type != "CNAME" || crr.Name != qname {
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
func (r *Resolver) saveDNSRR(host string, qname string, drrs []dns.RR) RRs {
	var rrs RRs
	cl := dns.CountLabel(qname)
	for _, drr := range drrs {
		rr, ok := convertRR(drr)
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
func (r *Resolver) cacheGet(qname string, qtype string) (RRs, error) {
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
