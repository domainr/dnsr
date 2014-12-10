package dnsr

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/miekg/dns"
)

var (
	DebugLogger    io.Writer
	Timeout        = 1000 * time.Millisecond
	MaxRecursion   = 10
	MaxNameservers = 2
	MaxIPs         = 2
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

// Resolve finds DNS records of type qtype for the domain qname. It returns a slice of *RR.
// For nonexistent domains (where a DNS server will return NXDOMAIN), it will return an empty, non-nil slice.
// Specify an empty string in qtype to receive any DNS records found (currently A, AAAA, NS, CNAME, and TXT).
func (r *Resolver) Resolve(qname string, qtype string) []*RR {
	return r.resolve(qname, qtype, 0)
}

func (r *Resolver) resolve(qname string, qtype string, depth int) []*RR {
	if depth++; depth > MaxRecursion {
		logMaxRecursion(qname, qtype, depth)
		return nil
	}
	qname = toLowerFQDN(qname)
	if rrs := r.cacheGet(qname, qtype); rrs != nil {
		return rrs
	}
	logResolveStart(qname, qtype, depth)
	defer logResolveEnd(qname, qtype, depth, time.Now())
	return r.resolveNS(qname, qtype, depth)
}

func (r *Resolver) resolveNS(qname string, qtype string, depth int) []*RR {
	success := make(chan bool, 1)
	for pname, ok := qname, true; ok; pname, ok = parent(pname) {
		if pname == qname && qtype == "NS" { // If we’re looking for [foo.com,NS], then skip to [com,NS]
			continue
		}

		// Query all DNS servers in parallel
		count := 0
		for _, nrr := range r.resolve(pname, "NS", depth) {
			if qtype != "" { // Early out for specific queries
				if rrs := r.cacheGet(qname, qtype); rrs != nil {
					return rrs
				}
			}
			if nrr.Type != "NS" {
				continue
			}
			if count++; count > MaxNameservers {
				break
			}
			go r.exchange(success, nrr.Value, qname, qtype, depth)
		}

		// Wait for first response
		if count > 0 {
			select {
			case <-success:
				return r.resolveCNAMEs(qname, qtype, depth)
			case <-time.After(Timeout):
				continue
			}
		}
	}
	return nil
}

func (r *Resolver) exchange(success chan<- bool, host string, qname string, qtype string, depth int) {
	dtype := dns.StringToType[qtype]
	if dtype == 0 {
		dtype = dns.TypeA
	}
	qmsg := &dns.Msg{}
	qmsg.SetQuestion(qname, dtype)
	qmsg.MsgHdr.RecursionDesired = false

	// Find each A record for the DNS server
	count := 0
	for _, rr := range r.resolve(host, "A", depth) {
		if rr.Type != "A" { // FIXME: support AAAA records?
			continue
		}

		// Never query more than MaxIPs for any nameserver
		if count++; count > MaxIPs {
			return
		}

		// Synchronously query this DNS server
		start := time.Now()
		rmsg, _, err := r.client.Exchange(qmsg, rr.Value+":53")
		logExchange(rr.Value, qmsg, depth, start, err)
		if err != nil {
			continue
		}

		// FIXME: cache NXDOMAIN responses responsibly
		if rmsg.Rcode == dns.RcodeNameError {
			r.cache.add(qname, nil)
		}

		// If successful, cache the results
		r.saveDNSRR(rmsg.Answer...)
		r.saveDNSRR(rmsg.Ns...)
		r.saveDNSRR(rmsg.Extra...)

		// Never block
		select {
		case success <- true:
		default:
		}

		// Return after first successful network request
		return
	}
}

func (r *Resolver) resolveCNAMEs(qname string, qtype string, depth int) []*RR {
	rrs := []*RR{} // Return non-nil slice indicating difference between NXDOMAIN and an error
	for _, crr := range r.cacheGet(qname, "") {
		rrs = append(rrs, crr)
		if crr.Type != "CNAME" {
			continue
		}
		logCNAME(depth, crr.String())
		for _, rr := range r.resolve(crr.Value, qtype, depth) {
			r.cache.add(qname, rr)
			rrs = append(rrs, crr)
		}
	}
	return rrs
}

func parent(name string) (string, bool) {
	labels := dns.SplitDomainName(name)
	if labels == nil {
		return "", false
	}
	return toLowerFQDN(strings.Join(labels[1:], ".")), true
}

func toLowerFQDN(name string) string {
	return dns.Fqdn(strings.ToLower(name))
}

func logMaxRecursion(qname string, qtype string, depth int) {
	if DebugLogger == nil {
		return
	}
	fmt.Fprintf(DebugLogger, "%s Error: MAX RECURSION @ %s %s %d\n",
		strings.Repeat("│   ", depth-1), qname, qtype, depth)
}

func logResolveStart(qname string, qtype string, depth int) {
	if DebugLogger == nil {
		return
	}
	fmt.Fprintf(DebugLogger, "%s┌─── resolve(\"%s\", \"%s\", %d)\n",
		strings.Repeat("│   ", depth-1), qname, qtype, depth)
}

func logResolveEnd(qname string, qtype string, depth int, start time.Time) {
	if DebugLogger == nil {
		return
	}
	dur := time.Since(start)
	fmt.Fprintf(DebugLogger, "%s└─── %dms: resolve(\"%s\", \"%s\", %d)\n",
		strings.Repeat("│   ", depth-1), dur/time.Millisecond, qname, qtype, depth)
}

func logCNAME(depth int, cname string) {
	if DebugLogger == nil {
		return
	}
	fmt.Fprintf(DebugLogger, "%s│    CNAME: %s\n", strings.Repeat("│   ", depth-1), cname)
}

func logExchange(host string, qmsg *dns.Msg, depth int, start time.Time, err error) {
	if DebugLogger == nil {
		return
	}
	dur := time.Since(start)
	fmt.Fprintf(DebugLogger, "%s│    %dms: dig @%s %s %s\n",
		strings.Repeat("│   ", depth-1), dur/time.Millisecond, host, qmsg.Question[0].Name, dns.TypeToString[qmsg.Question[0].Qtype])
	if err != nil {
		fmt.Fprintf(DebugLogger, "%s│    %dms: ERROR: %s\n",
			strings.Repeat("│   ", depth-1), dur/time.Millisecond, err.Error())
	}
}

// RR represents a DNS resource record.
type RR struct {
	Name  string
	Type  string
	Value string
}

// String returns a string representation of an RR in zone-file format.
func (rr *RR) String() string {
	return rr.Name + "\t      3600\tIN\t" + rr.Type + "\t" + rr.Value
}

func convertRR(drr dns.RR) *RR {
	switch t := drr.(type) {
	case *dns.NS:
		return &RR{t.Hdr.Name, dns.TypeToString[t.Hdr.Rrtype], t.Ns}
	case *dns.CNAME:
		return &RR{t.Hdr.Name, dns.TypeToString[t.Hdr.Rrtype], t.Target}
	case *dns.A:
		return &RR{t.Hdr.Name, dns.TypeToString[t.Hdr.Rrtype], t.A.String()}
	case *dns.AAAA:
		return &RR{t.Hdr.Name, dns.TypeToString[t.Hdr.Rrtype], t.AAAA.String()}
	case *dns.TXT:
		return &RR{t.Hdr.Name, dns.TypeToString[t.Hdr.Rrtype], strings.Join(t.Txt, "\t")}
	default:
		// fmt.Printf("%s\n", drr.String())
	}
	return nil
}

// saveDNSRR saves 1 or more DNS records to the resolver cache.
func (r *Resolver) saveDNSRR(drrs ...dns.RR) {
	for _, drr := range drrs {
		if rr := convertRR(drr); rr != nil {
			r.cache.add(rr.Name, rr)
		}
	}
}

// cacheGet returns a randomly ordered slice of DNS records.
func (r *Resolver) cacheGet(qname string, qtype string) []*RR {
	any := r.cache.get(qname)
	if any == nil {
		any = rootCache.get(qname)
	}
	if any == nil || len(any) == 0 {
		return any
	}
	rrs := make([]*RR, 0, len(any))
	for _, rr := range any {
		if qtype == "" || rr.Type == qtype {
			rrs = append(rrs, rr)
		}
	}
	if len(rrs) == 0 && (qtype != "" && qtype != "NS") {
		return nil
	}
	return rrs
}
