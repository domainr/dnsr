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

func (r *Resolver) Resolve(qname string, qtype dns.Type) <-chan dns.RR {
	c = make(chan dns.RR, 20)
	go func() {
		defer close(c)
		if rrs := r.cacheGet(qname, qtype); rrs != nil {
			for _, rr := range rrs {
				c <- rr
			}
			return
		}
		pname, ok := parent(qname)
		if !ok {
			return
		}
		for nrr := range r.Resolve(pname, dns.TypeNS) {
			ns, ok := nrr.(*dns.NS)
			if !ok {
				continue
			}
			for arr := range r.Resolve(ns.NS, dns.TypeA) {
				a, ok := arr.(*dns.A)
				if !ok {
					continue
				}
				addr := a.A.String() + ":53"
				qmsg := &dns.Msg{}
				qmsg.SetQuestion(q.Name, q.Qtype)
				qmsg.MsgHdr.RecursionDesired = false
				rmsg, _, err := r.client.Exchange(qmsg, addr)
				if err != nil {
					continue // FIXME: handle errors better from flaky/failing NS servers
				}
				if rmsg.Rcode == dns.RcodeNameError {
					r.cacheAdd(qname, qtype) // FIXME: cache NXDOMAIN responses responsibly
				}
				r.cacheSave(rmsg.Answer...)
				r.cacheSave(rmsg.Ns...)
				r.cacheSave(rmsg.Extra...)
				if r.cacheGet(qname, qtype) {
					return
				}
				break
			}
			break
		}
		for _, crr := range r.cacheGet(qname, dns.TypeCNAME) {
			cn, ok := rr.(*dns.CNAME)
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

func (r *Resolver) cacheRoot() {
	for t := range dns.ParseZone(strings.NewReader(root), "", "") {
		if t.Error == nil {
			r.cacheSave(t.RR)
		}
	}
}

// cacheGet returns a randomly ordered slice of DNS records
func (r *Resolver) cacheGet(qname string, qtype dns.Type) []dns.RR {
	e := r.getEntry(qname, qtype)
	if e == nil {
		return nil
	}
	e.m.RLock()
	defer e.m.RUnlock()
	rrs := make([]dns.RR, len(r.rrs))
	for rr, _ := range r.rrs {
		rrs = append(rrs, rr)
	}
}

func (r *Resolver) cacheSave(rrs ...dns.RR) {
	for _, rr := range rrs {
		h := rr.Header()
		r.cacheAdd(h.Name, h.Rrtype, rr)
	}
}

func (r *Resolver) cacheAdd(qname string, qtype dns.Type, rrs ...dns.RR) {
	now := time.Now()
	e := r.getEntry(qname, qtype)
	if e == nil {
		e = &entry{
			exp: now.Add(24 * time.Hour),
			rrs: make([]dns.RR, 0),
		}
		r.cache.Add(key{qname, qtype}, e)
	}
	e.m.Lock()
	defer e.m.Unlock()
	for _, rr := range rrs {
		e.rrs[rr] = struct{}{}
		exp := now.Add(rr.Header().Ttl * time.Second)
		if exp.Before(e.exp) {
			e.exp = exp
		}
	}
}

func (r *Resolver) getEntry(qname string, qtype dns.Type) *entry {
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

type key struct {
	qname string
	qtype dns.Type
}

type entry struct {
	m   sync.RWMutex
	exp time.Time
	rrs map[dns.RR]struct{}
}
