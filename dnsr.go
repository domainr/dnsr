package dnsr

import (
	"strings"
	"time"

	lru "github.com/hashicorp/golang-lru"
	"github.com/miekg/dns"
	"github.com/wsxiaoys/terminal/color"
)

type Resolver struct {
	cache *lru.Cache
}

func New(size int) *Resolver {
	if size < 0 {
		size = 10000
	}
	cache, _ := lru.New(size)
	r := &Resolver{cache}
	r.cacheRoot()
	return r
}

func (r *Resolver) cacheRoot() {
	for t := range dns.ParseZone(strings.NewReader(root), "", "") {
		if t.Error != nil {
			continue
		}
		r.cacheAdd([]dns.RR{t.RR})
	}
}

func (r *Resolver) Resolve(q dns.Question) []dns.RR {
	q = dns.Question{toLowerFQDN(q.Name), q.Qtype, q.Qclass}

	logV("@{};; QUESTION:\n%s\n\n\n", q.String())

	// Check cache
	rrs := r.cacheGet(q)
	if rrs != nil {
		logV("@{.};; CACHED:\n")
		for _, rr := range rrs {
			logV("@{.}%s\n", rr.String())
		}
		return rrs
	}

	// Find authorities (nameservers)
	nsName := q.Name
	if q.Qtype == dns.TypeNS {
		var ok bool
		// Query parent for NS queries
		nsName, ok = parent(q.Name)
		if !ok {
			logV("ERROR: tried to get parent of .\n")
			return nil
		}
	}
	nsQ := dns.Question{nsName, dns.TypeNS, q.Qclass}
	nses := r.Resolve(nsQ)
	if nses == nil {
		logV("@{r};; RESPONSE: no NS records found for %s\n", nsQ.Name)
		return nil
	}

	// Iterate through nameservers
	for _, rr := range nses {
		// Get authority’s A record
		ns := rr.(*dns.NS)
		ipQ := dns.Question{ns.Ns, dns.TypeA, q.Qclass}
		ips := r.Resolve(ipQ)
		if ips == nil {
			logV("@{r};; RESPONSE: no A records found for %s\n", ipQ.Name)
			continue
		}

		// Iterate through IP addresses
		for _, rr := range ips {
			qMsg := &dns.Msg{}
			qMsg.SetQuestion(q.Name, q.Qtype)
			qMsg.MsgHdr.RecursionDesired = false
			ip := rr.(*dns.A)
			addr := ip.A.String() + ":53"
			client := &dns.Client{}
			rMsg, _, err := client.Exchange(qMsg, addr)
			if err != nil {
				logV("@{r};; ERROR: %s\n", err.Error())
				continue
			}

			// FIXME: cache NXDOMAIN responses responsibly
			if rMsg.Rcode == dns.RcodeNameError {
				r.cacheSet(q, []dns.RR{})
			}

			// Log responses
			logV("@{c};; ANSWER:\n")
			for _, rr := range rMsg.Answer {
				logV("@{c}%s\n", rr.String())
			}
			logV("@{c}\n;; AUTHORITY:\n")
			for _, rr := range rMsg.Ns {
				logV("@{c}%s\n", rr.String())
			}
			logV("@{c}\n;; EXTRA:\n")
			for _, rr := range rMsg.Extra {
				logV("@{c}%s\n", rr.String())
			}

			// Cache responses
			r.cacheAdd(rMsg.Answer)
			r.cacheAdd(rMsg.Ns)
			r.cacheAdd(rMsg.Extra)

			// Check cache again
			rrs := r.cacheGet(q)
			if rrs != nil {
				return rrs
			}

			break
		}

		break
	}

	// Only check CNAMES for A and AAAA questions
	if q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA {
		return nil
	}

	// Check cache for CNAMEs
	cQ := dns.Question{q.Name, dns.TypeCNAME, q.Qclass}
	rrs = r.cacheGet(cQ)
	if rrs != nil {
		// Iterate through CNAMEs
		for _, rr := range rrs {

			// Get CNAME target
			cn := rr.(*dns.CNAME)
			cQ2 := dns.Question{cn.Target, q.Qtype, q.Qclass}
			cns := r.Resolve(cQ2)
			if cns == nil {
				logV("@{r};; RESPONSE: no records found for CNAME %s\n", cQ2.Name)
				continue
			}

			return cns
		}
	}

	return nil
}

func (r *Resolver) cacheGet(q dns.Question) []dns.RR {
	c, ok := r.cache.Get(q)
	if !ok {
		return nil
	}
	e := c.(*entry)
	if e.isExpired() {
		return nil
	}
	return e.records
}

func (r *Resolver) cacheAdd(rrs []dns.RR) {
	if len(rrs) == 0 {
		return
	}
	h := rrs[0].Header()
	q := dns.Question{toLowerFQDN(h.Name), h.Rrtype, h.Class}
	r.cacheSet(q, rrs)
}

func (r *Resolver) cacheSet(q dns.Question, rrs []dns.RR) {
	var ttl uint32 = 3600
	if len(rrs) > 0 {
		ttl = rrs[0].Header().Ttl
		for _, rr := range rrs {
			if rr.Header().Ttl < ttl {
				ttl = rr.Header().Ttl
			}
		}
	}
	exp := time.Now().Add(time.Duration(ttl) * time.Second)
	e := &entry{exp, rrs}
	r.cache.Add(q, e)
}

type entry struct {
	expiry  time.Time
	records []dns.RR
}

func (e *entry) isExpired() bool {
	if time.Now().After(e.expiry) {
		return true
	}
	return false
}

func toLowerFQDN(name string) string {
	return dns.Fqdn(strings.ToLower(name))
}

func parent(name string) (string, bool) {
	labels := dns.SplitDomainName(name)
	if labels == nil {
		return "", false
	}
	return toLowerFQDN(strings.Join(labels[1:], ".")), true
}

var Verbose = false

func logV(fmt string, args ...interface{}) {
	// if !Verbose {
	// 	return
	// }
	color.Printf(fmt, args...)
}
