package dnsr

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru"
	"github.com/miekg/dns"
)

//go:generate sh generate.sh

var (
	Root           *Resolver
	DebugLogger    io.Writer
	Timeout        = 1000 * time.Millisecond
	MaxRecursion   = 10
	MaxNameservers = 2
	MaxIPs         = 2
)

func init() {
	Root = New(strings.Count(root, "\n"))
	for t := range dns.ParseZone(strings.NewReader(root), "", "") {
		if t.Error == nil {
			Root.saveDNSRR(t.RR)
		}
	}
}

// Resolver implements a primitive, non-recursive, caching DNS resolver.
type Resolver struct {
	cache  *lru.Cache
	client *dns.Client
}

// New initializes a Resolver with the specified cache size. Cache size defaults to 10,000 if size <= 0.
func New(size int) *Resolver {
	if size <= 0 {
		size = 10000
	}
	cache, _ := lru.New(size)
	r := &Resolver{
		client: &dns.Client{
			DialTimeout:  Timeout,
			ReadTimeout:  Timeout,
			WriteTimeout: Timeout,
		},
		cache: cache,
	}
	return r
}

// Resolve finds DNS records of type qtype for the domain qname. It returns a channel of *RR.
// The implementation guarantees that the output channel will close, so it is safe to range over.
// For nonexistent domains (where a DNS server will return NXDOMAIN), it will simply close the output channel.
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
			r.cacheAdd(qname, nil)
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
			r.cacheAdd(qname, rr)
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
	fmt.Printf("%s Error: MAX RECURSION @ %s %s %d\n",
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

type key struct {
	Name string
	Type string
}

type entry struct {
	m   sync.RWMutex
	rrs map[RR]struct{}
}

// saveDNSRR saves 1 or more DNS records to the resolver cache.
func (r *Resolver) saveDNSRR(drrs ...dns.RR) {
	for _, drr := range drrs {
		if rr := convertRR(drr); rr != nil {
			r.cacheAdd(rr.Name, rr)
		}
	}
}

// cacheAdd adds 0 or more DNS records to the resolver cache for a specific
// domain name and record type. This ensures the cache entry exists, even
// if empty, for NXDOMAIN responses.
func (r *Resolver) cacheAdd(qname string, rr *RR) {
	qname = toLowerFQDN(qname)
	e := r.getEntry(qname)
	if e == nil {
		e = &entry{rrs: make(map[RR]struct{}, 0)}
		e.m.Lock()
		r.cache.Add(qname, e)
	} else {
		e.m.Lock()
	}
	defer e.m.Unlock()
	if rr != nil {
		e.rrs[*rr] = struct{}{}
	}
}

// cacheGet returns a randomly ordered slice of DNS records.
func (r *Resolver) cacheGet(qname string, qtype string) []*RR {
	e := r.getEntry(qname)
	if e == nil && r != Root {
		e = Root.getEntry(qname)
	}
	if e == nil {
		return nil
	}
	e.m.RLock()
	defer e.m.RUnlock()
	if len(e.rrs) == 0 {
		return []*RR{}
	}
	rrs := make([]*RR, 0, len(e.rrs))
	for rr, _ := range e.rrs {
		// fmt.Printf("%s\n", rr.String())
		if qtype == "" || rr.Type == qtype {
			rrs = append(rrs, &RR{rr.Name, rr.Type, rr.Value})
		}
	}
	if len(rrs) == 0 && (qtype != "" && qtype != "NS") {
		return nil
	}
	return rrs
}

// getEntry returns a single cache entry or nil if an entry does not exist in the cache.
func (r *Resolver) getEntry(qname string) *entry {
	c, ok := r.cache.Get(qname)
	if !ok {
		return nil
	}
	e, ok := c.(*entry)
	if !ok {
		return nil
	}
	return e
}
