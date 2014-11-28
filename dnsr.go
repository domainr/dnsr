package dnsr

import (
	"fmt"
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
		q := &dns.Question{qname, qtype, dns.ClassINET}
		defer fmt.Printf(";; QUESTION:\n%s\n\n\n", q.String())
		defer close(c)
		qname = toLowerFQDN(qname)
		if rrs := r.cacheGet(qname, qtype); rrs != nil {
			inject(c, rrs...)
			return
		}
		pname, ok := qname, true
		if qtype == dns.TypeNS {
			pname, ok = parent(qname)
			if !ok {
				return
			}
		}
		for nrr := range r.Resolve(pname, dns.TypeNS) {
			ns, ok := nrr.(*dns.NS)
			if !ok {
				continue
			}
		outer:
			for arr := range r.Resolve(ns.Ns, dns.TypeA) {
				a, ok := arr.(*dns.A)
				if !ok {
					continue
				}
				addr := a.A.String() + ":53"
				qmsg := &dns.Msg{}
				qmsg.SetQuestion(qname, qtype)
				qmsg.MsgHdr.RecursionDesired = false
				fmt.Printf("; Querying DNS server %s for %s\n", addr, qname)
				rmsg, _, err := r.client.Exchange(qmsg, addr)
				if err != nil {
					fmt.Printf("; ERROR querying DNS server %s for %s: %s\n", addr, qname, err.Error())
					continue // FIXME: handle errors better from flaky/failing NS servers
				}
				if rmsg.Rcode == dns.RcodeNameError {
					r.cacheAdd(qname, qtype) // FIXME: cache NXDOMAIN responses responsibly
				}
				r.cacheSave(rmsg.Answer...)
				r.cacheSave(rmsg.Ns...)
				r.cacheSave(rmsg.Extra...)
				if rrs := r.cacheGet(qname, qtype); rrs != nil {
					inject(c, rrs...)
					return
				}
				break outer
			}
		}
		for _, crr := range r.cacheGet(qname, dns.TypeCNAME) {
			cn, ok := crr.(*dns.CNAME)
			if !ok {
				continue
			}
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
		fmt.Printf("%s\n", rr.String())
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
	rrs map[dns.RR]struct{}
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
	for rr, _ := range e.rrs {
		rrs = append(rrs, rr)
	}
	return rrs
}

// cacheSave saves 1 or more DNS records to the resolver cache.
func (r *Resolver) cacheSave(rrs ...dns.RR) {
	for _, rr := range rrs {
		h := rr.Header()
		r.cacheAdd(toLowerFQDN(h.Name), h.Rrtype, rr)
	}
}

// cacheAdd adds 0 or more DNS records to the resolver cache for a specific
// domain name and record type. This ensures the cache entry exists, even
// if empty, for NXDOMAIN responses.
func (r *Resolver) cacheAdd(qname string, qtype uint16, rrs ...dns.RR) {
	now := time.Now()
	e := r.getEntry(qname, qtype)
	if e == nil {
		e = &entry{
			exp: now.Add(24 * time.Hour),
			rrs: make(map[dns.RR]struct{}, 0),
		}
		r.cache.Add(key{qname, qtype}, e)
	}
	e.m.Lock()
	defer e.m.Unlock()
	for _, rr := range rrs {
		e.rrs[rr] = struct{}{}
		exp := now.Add(time.Duration(rr.Header().Ttl) * time.Second)
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
