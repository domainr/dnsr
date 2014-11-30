package dnsr

import (
	"strings"
	"sync"

	lru "github.com/hashicorp/golang-lru"
	"github.com/miekg/dns"
)

type Resolver struct {
	cache  *lru.Cache
	client *dns.Client
}

func New(size int) *Resolver {
	if size <= 0 {
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

func (r *Resolver) Resolve(qname string) <-chan *RR {
	c := make(chan *RR, 20)
	go func() {
		qname = toLowerFQDN(qname)
		defer close(c)
		if rrs := r.cacheGet(qname); rrs != nil {
			inject(c, rrs...)
			return
		}
		pname, ok := parent(qname)
	outer:
		for ; ok; pname, ok = parent(pname) {
			for nrr := range r.Resolve(pname) {
				if nrr.Type != "NS" {
					continue
				}
				for arr := range r.Resolve(nrr.Value) {
					if arr.Type != "A" { // FIXME: support AAAA records?
						continue
					}
					addr := arr.Value + ":53"
					qmsg := &dns.Msg{}
					qmsg.SetQuestion(qname, dns.TypeA)
					qmsg.MsgHdr.RecursionDesired = false
					// fmt.Printf(";; dig +norecurse @%s %s %s\n", a.A.String(), qname, dns.TypeToString[qtype])
					rmsg, _, err := r.client.Exchange(qmsg, addr)
					if err != nil {
						continue // FIXME: handle errors better from flaky/failing NS servers
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

		if rrs := r.cacheGet(qname); rrs != nil {
			inject(c, rrs...)
			//return
		}

		// FIXME: will it ever make it here?
		for _, crr := range r.cacheGet(qname) {
			if crr.Type != "CNAME" {
				continue
			}
			for rr := range r.Resolve(crr.Value) {
				r.cacheAdd(qname, rr)
				c <- rr
			}
		}
	}()
	return c
}

type RR struct {
	Name  string
	Type  string
	Value string
}

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
	}
	return nil
}

func inject(c chan<- *RR, rrs ...*RR) {
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

type entry struct {
	m   sync.RWMutex
	rrs map[RR]struct{}
}

func (r *Resolver) cacheRoot() {
	for t := range dns.ParseZone(strings.NewReader(root), "", "") {
		if t.Error == nil {
			r.saveDNSRR(t.RR)
		}
	}
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
func (r *Resolver) cacheGet(qname string) []*RR {
	e := r.getEntry(qname)
	if e == nil {
		return nil
	}
	e.m.RLock()
	defer e.m.RUnlock()
	rrs := make([]*RR, 0, len(e.rrs))
	for rr, _ := range e.rrs {
		rrs = append(rrs, &rr)
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
