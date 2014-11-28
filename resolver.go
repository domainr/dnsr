package dnsr

import (
	"strings"

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
		if rrs := r.recall(qname, qtype); rrs != nil {
			inject(c, rrs)
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
					r.rememberFor(qname, qtype) // FIXME: cache NXDOMAIN responses responsibly
				}
				r.remember(rmsg.Answer...)
				r.remember(rmsg.Ns...)
				r.remember(rmsg.Extra...)
				if r.recall(qname, qtype) {
					return
				}
				break
			}
			break
		}
		
		for _, crr := range r.recall(qname, dns.TypeCNAME) {
			cn, ok := rr.(*dns.CNAME)
			if !ok {
				continue
			}
			for rr := range r.Resolve(cn.Target, qtype) {
				r.rememberFor(qname, qtype, rr)
				c <- rr
			}
		}
	}()
	return c
}

func (r *Resolver) cacheRoot() {
	for t := range dns.ParseZone(strings.NewReader(root), "", "") {
		if t.Error == nil {
			r.remember(t.RR)
		}
	}
}

func (r *Resolver) recall(qname string, qtype dns.Type) []dns.RR {
	// FIXME: implement
	return nil
}

func (r *Resolver) remember(rrs ...dns.RR) {
	// FIXME: implement
}

func (r *Resolver) rememberFor(qname string, qtype dns.Type, rrs ...dns.RR) {
	// FIXME: implement
}

func inject(c chan<- dns.RR, rrs []dns.RR) {
	for _, rr := range rrs {
		c <- rr
	}
}
