package dnsr

import "sync"

type cache struct {
	maxSize int
	m       sync.RWMutex
	entries map[string]entry
}

type entry struct {
	m   sync.RWMutex
	rrs map[RR]struct{}
}

// add adds 0 or more DNS records to the resolver cache for a specific
// domain name and record type. This ensures the cache entry exists, even
// if empty, for NXDOMAIN responses.
func (c *cache) add(qname string, rrs ...*RR) {
	qname = toLowerFQDN(qname)
	c.m.Lock()
	defer c.m.Unlock()
	e, ok := c.entries[qname]
	if !ok {
		e = entry{rrs: make(map[RR]struct{}, 0)}
		c.entries[qname] = e
	}
	for _, rr := range rrs {
		e.rrs[*rr] = struct{}{}
	}
}

// get returns a randomly ordered slice of DNS records.
func (c *cache) get(qname string, qtype string) []*RR {
	c.m.RLock()
	defer c.m.RUnlock()
	e, ok := c.entries[qname]
	if !ok {
		return nil
	}
	if len(e.rrs) == 0 {
		return []*RR{}
	}
	i := 0
	rrs := make([]*RR, 0, len(e.rrs))
	for rr, _ := range e.rrs {
		if qtype == "" || rr.Type == qtype {
			rrs[i] = &RR{rr.Name, rr.Type, rr.Value}
			i++
		}
	}
	if len(rrs) == 0 && (qtype != "" && qtype != "NS") {
		return nil
	}
	return rrs
}
