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
	Root        *Resolver
	DebugLogger io.Writer
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
		client: &dns.Client{},
		cache:  cache,
	}
	return r
}

// Resolve finds DNS records of type qtype for the domain qname. It returns a channel of *RR.
// The implementation guarantees that the output channel will close, so it is safe to range over.
// For nonexistent domains (where a DNS server will return NXDOMAIN), it will simply close the output channel.
// Specify an empty string in qtype to receive any DNS records found (currently A, AAAA, NS, CNAME, and TXT).
func (r *Resolver) Resolve(qname string, qtype string) <-chan *RR {
	return r.resolve(qname, qtype, 0)
}

func (r *Resolver) resolve(qname string, qtype string, depth int) <-chan *RR {
	c := make(chan *RR, 20)
	go func() {
		if DebugLogger != nil {
			start := time.Now()
			defer func() {
				dur := time.Since(start)
				if dur >= 1*time.Millisecond {
					fmt.Fprintf(DebugLogger, "%s└─── %dms: resolve(\"%s\", \"%s\")\n",
						strings.Repeat("│   ", depth), dur/time.Millisecond, qname, qtype)
				}
			}()
		}
		qname = toLowerFQDN(qname)
		defer close(c)
		if rrs := r.cacheGet(qname, qtype); rrs != nil {
			inject(c, rrs...)
			return
		}
		if DebugLogger != nil {
			fmt.Fprintf(DebugLogger, "%s┌─── resolve(\"%s\", \"%s\")\n",
				strings.Repeat("│   ", depth), qname, qtype)
		}
		pname, ok := qname, true
		if qtype == "NS" {
			pname, ok = parent(qname)
			if !ok {
				return
			}
		}
	outer:
		for ; ok; pname, ok = parent(pname) {
			for nrr := range r.resolve(pname, "NS", depth+1) {
				if nrr.Type != "NS" {
					continue
				}
				for arr := range r.resolve(nrr.Value, "A", depth+1) {
					if arr.Type != "A" { // FIXME: support AAAA records?
						continue
					}
					addr := arr.Value + ":53"
					dtype, ok := dns.StringToType[qtype]
					if !ok {
						dtype = dns.TypeA
					}
					qmsg := &dns.Msg{}
					qmsg.SetQuestion(qname, dtype)
					qmsg.MsgHdr.RecursionDesired = false
					// fmt.Printf(";; dig +norecurse @%s %s %s\n", a.A.String(), qname, dns.TypeToString[qtype])
					rmsg, dur, err := r.client.Exchange(qmsg, addr)
					if err != nil {
						continue // FIXME: handle errors better from flaky/failing NS servers
					}
					if DebugLogger != nil {
						fmt.Fprintf(DebugLogger, "%s│    %dms: dig @%s %s %s\n", strings.Repeat("│   ", depth), dur/time.Millisecond, arr.Value, qname, qtype)
					}
					r.saveDNSRR(rmsg.Answer...)
					r.saveDNSRR(rmsg.Ns...)
					r.saveDNSRR(rmsg.Extra...)
					if rmsg.Rcode == dns.RcodeNameError {
						r.cacheAdd(qname, nil) // FIXME: cache NXDOMAIN responses responsibly
						return
					}
					break outer
				}
			}
		}

		if rrs := r.cacheGet(qname, ""); rrs != nil {
			if !inject(c, rrs...) {
				return
			}

			for _, crr := range rrs {
				if crr.Type != "CNAME" {
					continue
				}
				// fmt.Printf("Checking CNAME: %s\n", crr.String())
				for rr := range r.resolve(crr.Value, qtype, depth+1) {
					r.cacheAdd(qname, rr)
					if !inject(c, rr) {
						return
					}
				}
			}
		}
	}()
	return c
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

func inject(c chan<- *RR, rrs ...*RR) bool {
	for _, rr := range rrs {
		select {
		case c <- rr:
		default:
			// return false
		}
	}
	return true
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
