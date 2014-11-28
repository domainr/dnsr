package dnsr

import (
	lru "github.com/hashicorp/golang-lru"
	"github.com/miekg/dns"
)

type Resolver struct {
	cache *lru.Cache
}

func (r *Resolver) Resolve(qname string, qtype dns.Type) *Worker {
	w := &Worker{
		r: r,
		qname: qname,
		qtype: qtype,
		done: make(chan struct{}),
		RRs: make(chan dns.RR, 20),
	}
	go w.Start()
	return w
}

func (r *Resolver) recall(qname, qtype) ([]dns.RR, bool) {
	// FIXME: implement
	return []dns.RR{}, false
}

func (r *Resolver) remember(rr ...dns.RR) {
	// FIXME: implement
}

func (r *Resolver) rememberNX(qname, qtype) {
	// FIXME: implement
}


type Worker struct {
	r     *Resolver
	qname string
	qtype dns.Type
	done  chan struct{}
	RRs   chan dns.RR
}

func (w *Worker) Start() {
	defer w.Stop()
	rrs, ok := w.r.recall(w.qname, w.qtype)
	if ok {
		inject(w.RRs, rrs)
		return
	}
	w.resolveViaAuthorities()
}

func (w *Worker) Stop() {
	close(w.done)
	close(w.RRs)
}

func (w *Worker) resolveViaAuthorities() {
	pname, ok = parent(w.qname)
	if !ok {
		return
	}
	for rr := range w.r.Resolve(pname, dns.TypeNS).RRs {
		ns, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		w.resolveViaAuthority(ns.NS)
	}
}

func (w *Worker) resolveViaAuthority(nsname) {
	for rr := range w.r.Resolve(nsname, dns.TypeA).RRs {
		a, ok := rr.(*dns.A)
		if !ok {
			continue
		}
		addr := a.A.String() + ":53"
		w.resolveViaServer(addr)
	}
}

func (w *Worker) resolveViaServer(addr) {
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
		w.r.rememberNX(qname, qtype)
	}

	// Cache responses
	w.r.remember(rMsg.Answer...)
	w.r.remember(rMsg.Ns...)
	w.r.remember(rMsg.Extra...)

	// Check cache again
	rrs, ok := w.r.recall(q)
	if ok {
		inject(c, rrs)
		return
	}
}

func inject(c chan<- dns.RR, rrs []dns.RR) {
	for _, rr := range rrs {
		c <- rr
	}
}
