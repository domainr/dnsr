package dnsr

import (
	"strings"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru"
	"github.com/miekg/dns"
)

type Resolver struct {
	cache  *lru.Cache
	client *dns.Client
}

func New(size int) *Resolver {
	if size < 0 {
		size = 10000
	}
	cache, _ := lru.New(size)
	r := &Resolver{
		client: &dns.Client{},
		cache:  cache,
	}
	r.cacheRoot()
	return r
}

func (r *Resolver) Resolve(qname string, qtype uint16) <-chan dns.RR {
	c := make(chan dns.RR, 20)
	go func() {
		qname = toLowerFQDN(qname)
		defer close(c)
		if rrs := r.cacheGet(qname, qtype); rrs != nil {
			inject(c, rrs...)
			return
		}
		pname, ok := qname, true
		if qtype == dns.TypeNS {
			pname, ok = parent(qname)
		}
	outer:
		for ; ok; pname, ok = parent(pname) {
			for nrr := range r.Resolve(pname, dns.TypeNS) {
				ns, ok := nrr.(*dns.NS)
				if !ok {
					continue
				}
				for arr := range r.Resolve(ns.Ns, dns.TypeA) {
					a, ok := arr.(*dns.A)
					if !ok {
						continue
					}
					addr := a.A.String() + ":53"
					qmsg := &dns.Msg{}
					qmsg.SetQuestion(qname, qtype)
					qmsg.MsgHdr.RecursionDesired = false
					// fmt.Printf(";; dig +norecurse @%s %s %s\n", a.A.String(), qname, dns.TypeToString[qtype])
					rmsg, _, err := r.client.Exchange(qmsg, addr)
					if err != nil {
						continue // FIXME: handle errors better from flaky/failing NS servers
					}
					r.cacheSave(rmsg.Answer...)
					r.cacheSave(rmsg.Ns...)
					r.cacheSave(rmsg.Extra...)
					if rmsg.Rcode == dns.RcodeNameError {
						r.cacheAdd(qname, qtype) // FIXME: cache NXDOMAIN responses responsibly
						return
					}
					break outer
				}
			}
		}

		if rrs := r.cacheGet(qname, qtype); rrs != nil {
			inject(c, rrs...)
			return
		}

		for _, crr := range r.cacheGet(qname, dns.TypeCNAME) {
			cn, ok := crr.(*dns.CNAME)
			if !ok {
				continue
			}
			r.cacheAdd(qname, qtype, crr)
			for rr := range r.Resolve(cn.Target, qtype) {
				r.cacheAdd(qname, qtype, rr)
				c <- rr
			}
		}
	}()
	return c
}

func inject(c chan<- dns.RR, rrs ...dns.RR) {
	for _, rr := range rrs {
		c <- rr
	}
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
	qname string
	qtype uint16
}

type entry struct {
	m   sync.RWMutex
	exp time.Time
	rrs map[string]dns.RR
}

func (r *Resolver) cacheRoot() {
	for t := range dns.ParseZone(strings.NewReader(root), "", "") {
		if t.Error == nil {
			r.cacheSave(t.RR)
		}
	}
}

// cacheGet returns a randomly ordered slice of DNS records.
func (r *Resolver) cacheGet(qname string, qtype uint16) []dns.RR {
	e := r.getEntry(qname, qtype)
	if e == nil {
		return nil
	}
	e.m.RLock()
	defer e.m.RUnlock()
	rrs := make([]dns.RR, 0, len(e.rrs))
	for _, rr := range e.rrs {
		rrs = append(rrs, rr)
	}
	return rrs
}

// cacheSave saves 1 or more DNS records to the resolver cache.
func (r *Resolver) cacheSave(rrs ...dns.RR) {
	for _, rr := range rrs {
		h := rr.Header()
		r.cacheAdd(h.Name, h.Rrtype, rr)
	}
}

// cacheAdd adds 0 or more DNS records to the resolver cache for a specific
// domain name and record type. This ensures the cache entry exists, even
// if empty, for NXDOMAIN responses.
func (r *Resolver) cacheAdd(qname string, qtype uint16, rrs ...dns.RR) {
	qname = toLowerFQDN(qname)
	now := time.Now()
	e := r.getEntry(qname, qtype)
	if e == nil {
		e = &entry{
			exp: now.Add(24 * time.Hour),
			rrs: make(map[string]dns.RR, 0),
		}
		r.cache.Add(key{qname, qtype}, e)
	}
	e.m.Lock()
	defer e.m.Unlock()
	for _, rr := range rrs {
		h := rr.Header()
		if h.Rrtype != qtype {
			continue
		}
		e.rrs[rr.String()] = rr
		exp := now.Add(time.Duration(h.Ttl) * time.Second)
		if exp.Before(e.exp) {
			e.exp = exp
		}
	}
}

func (r *Resolver) getEntry(qname string, qtype uint16) *entry {
	c, ok := r.cache.Get(key{qname, qtype})
	if !ok {
		return nil
	}
	e := c.(*entry)
	if time.Now().After(e.exp) {
		return nil
	}
	return e
}
