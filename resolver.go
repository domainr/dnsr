package dnsr

import "github.com/miekg/dns"

type Resolver interface {
	Resolve(qname string, qtype dns.Type) ([]dns.RR, error)
}

type baseResolver struct {
	cache Resolver
}

func (r *baseResolver) Resolve(qname string, qtype dns.Type) ([]dns.RR, error) {
	rrs, err := r.resolveViaCache(qname, qtype)
	if err != nil {
		return nil, err
	}
	if rrs != nil {
		return rrs, nil
	}
	return r.resolveViaAuthority(qname, qtype)
}

func (r *baseResolver) resolveViaAuthority(qname string, qtype dns.Type) ([]dns.RR, error) {
	rrs, err := r.Resolve(qname, dns.TypeNS)
	if err != nil {
		return nil, err
	}
	return r.resolveViaAuthorities(rrs, qname, qtype)
}

func (r *baseResolver) resolveViaAuthorities(authorities []dns.RR, qname string, qtype dns.Type) ([]dns.RR, error) {
	for _, auth := range authorities {
		ns, ok := auth.(*dns.NS)
		if !ok {
			continue
		}
		arecords, err := r.Resolve(ns.NS, dns.TypeA)
		if err != nil {
			continue
		}
		return r.resolveViaAddresses(arecords, qname, qtype)
	}
	return nil, nil
}


type RecordStream <-chan dns.RR


type Ints chan int
func (c Ints) Positive() Ints {
	out := make(chan int)
	for i := range c {
		if i > 0 {
			out <- i
		}
	}
}

func (c Ints) Select(func(i int) bool) {
	out := make(chan int)
	for i := range c {
		if i > 0 {
			out <- i
		}
	}
}




func (r *resolver) Resolve(qname string, qtype dns.Type) RecordStream {
	return cache.Resolve(qname, qtype).Fallback
}

// type CachingResolver
// type FilteredResolver





type fallbackResolver struct {
	primary  Resolver
	fallback Resolver
}

func (r *fallbackResolver) Resolve(qname string, qtype dns.Type) ([]dns.RR, error) {
	rrs, err := r.primary.Resolve(qname, qtype)
	if rrs != nil && err == nil {
		return rrs, err
	}
	return r.fallback.Resolve(qname, qtype)
}

type authorityForNameResolver struct {
	name string
}

func (r *authorityForNameResolver) Resolve(qname string, qtype dns.Type) ([]dns.RR, error) {
	auths, err := r.primary.Resolve(r.name, dns.TypeNS)
}

type authoritiesResolver struct {
	authorities []string
}
