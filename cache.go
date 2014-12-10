package dnsr

import "sync"

type cache struct {
	capacity int
	m        sync.RWMutex
	entries  map[string]entry
}

type entry struct {
	rrs map[RR]struct{}
}

// newCache initializes and returns a new cache instance.
// Capacity defaults to 10,000 if size <= 0.
func newCache(capacity int) *cache {
	if capacity <= 0 {
		capacity = 10000
	}
	return &cache{
		capacity: capacity,
		entries: make(map[string]entry),
	}
}

// add adds 0 or more DNS records to the resolver cache for a specific
// domain name and record type. This ensures the cache entry exists, even
// if empty, for NXDOMAIN responses.
func (c *cache) add(qname string, rr *RR) {
	qname = toLowerFQDN(qname)
	c.m.Lock()
	defer c.m.Unlock()
	e, ok := c.entries[qname]
	if !ok {
		c._evict()
		e = entry{rrs: make(map[RR]struct{}, 0)}
		c.entries[qname] = e
	}
	if rr != nil {
		e.rrs[*rr] = struct{}{}
	}
}

// FIXME: better random cache eviction than Go’s random key guarantee?
func (c *cache) _evict() {
	if len(c.entries) < c.capacity {
		return
	}
	for k := range c.entries {
		delete(c.entries, k)
		if len(c.entries) < c.capacity {
			return
		}
	}
}

// get returns a randomly ordered slice of DNS records.
func (c *cache) get(qname string) []*RR {
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
	rrs := make([]*RR, len(e.rrs))
	for rr, _ := range e.rrs {
		rrs[i] = &RR{rr.Name, rr.Type, rr.Value} // Don’t return a pointer to a map key
		i++
	}
	return rrs
}
