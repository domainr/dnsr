package dnsr

import "github.com/miekg/dns"

type Resolver struct {
	cache Resolver
}

func (r *Resolver) Resolve(qname string, qtype dns.Type) <-chan dns.RR {
	c := make(chan dns.RR, 20)
	go func() {
		defer close(c)
		rrs, ok := r.cacheGet(qname, qtype)
		if ok {
			inject(c, rrs)
			return
		}
		r.resolveViaAuthorities(c, qname, qtype)
	}
	return c
}

func (r *Resolver) resolveViaAuthorities(c chan<- dns.RR, qname string, qtype dns.Type) {
	pname, ok = parent(qname)
	if !ok {
		return
	}
	for rr := range r.Resolve(pname, dns.TypeNS) {
		ns, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		r.resolveViaAuthority(c, ns.NS, qname, qtype)
	}
}

func (r *Resolver) resolveViaAuthority(c chan<- dns.RR, nsname, qname string, qtype dns.Type) {
	for rr := range r.Resolve(nsname, dns.TypeA) {
		a, ok := rr.(*dns.A)
		if !ok {
			continue
		}
		addr := a.A.String() + ":53"
		r.exchange(c, addr, qname, qtype)
	}
}

func (r *Resolver) resolveViaServer(c chan<- dns.RR, addr, qname string, qtype dns.Type) {
	msg := &dns.Msg{}
	msg.SetQuestion(q.Name, q.Qtype)
	msg.MsgHdr.RecursionDesired = false
	client := &dns.Client{}
	rmsg, _, err := client.Exchange(msg, addr)
	if err != nil {
		return
	}

	// FIXME: cache NXDOMAIN responses responsibly
	if rmsg.Rcode == dns.RcodeNameError {
		r.cacheSetEmpty(qname, qtype)
	}

	// Cache responses
	r.cacheAdd(rMsg.Answer...)
	r.cacheAdd(rMsg.Ns...)
	r.cacheAdd(rMsg.Extra...)

	// Check cache again
	rrs, ok := r.cacheGet(q)
	if ok {
		inject(c, rrs)
		return
	}
}

func (r *Resolver) cacheGet(qname, qtype) ([]dns.RR, bool) {
	// FIXME: implement
	return []dns.RR{}
}

func (r *Resolver) cacheAdd(rr ...dns.RR) {
	// FIXME: implement
}

func (r *Resolver) cacheSetEmpty(qname, qtype) {
	// FIXME: implement
}

func inject(c chan<- dns.RR, rrs []dns.RR) {
	for _, rr := range rrs {
		c <- rr
	}
}
