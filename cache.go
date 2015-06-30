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

const MinCacheCapacity = 1000

// newCache initializes and returns a new cache instance.
// Cache capacity defaults to MinCacheCapacity if <= 0.
func newCache(capacity int) *cache {
	if capacity <= 0 {
		capacity = MinCacheCapacity
	}
	return &cache{
		capacity: capacity,
		entries:  make(map[string]entry),
	}
}

// add adds 0 or more DNS records to the resolver cache for a specific
// domain name and record type. This ensures the cache entry exists, even
// if empty, for NXDOMAIN responses.
func (c *cache) add(qname string, rrs ...*RR) {
	qname = toLowerFQDN(qname) // FIXME: optimize this away
	c.m.Lock()
	defer c.m.Unlock()
	for _, rr := range rrs {
		c._add(qname, rr)
	}
}

// _add does NOT lock the mutex so unsafe for concurrent usage.
func (c *cache) _add(qname string, rr *RR) {
	e, ok := c.entries[qname]
	if !ok {
		c._evict()
		// For NXDOMAIN responses,
		// the cache entry is present, but nil.
		c.entries[qname] = entry{}
	}
	if e.rrs == nil && rr != nil {
		e.rrs = make(map[RR]struct{}, 0)
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
		return emptyRRs
	}
	i := 0
	rrs := make([]*RR, len(e.rrs))
	for rr, _ := range e.rrs {
		rrs[i] = &RR{rr.Name, rr.Type, rr.Value} // Don’t return a pointer to a map key
		i++
	}
	return rrs
}
