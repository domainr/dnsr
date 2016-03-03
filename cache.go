package dnsr

import "sync"

type cache struct {
	capacity int
	m        sync.RWMutex
	entries  map[string]entry
}

type entry map[RR]struct{}

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
func (c *cache) add(qname string, rr RR) {
	c.m.Lock()
	c._add(qname, rr)
	c.m.Unlock()
}

// addNX adds an NXDOMAIN to the cache.
// Safe for concurrent usage.
func (c *cache) addNX(qname string) {
	c.m.Lock()
	c._addEntry(qname)
	c.m.Unlock()
}

// _add does NOT lock the mutex so unsafe for concurrent usage.
func (c *cache) _add(qname string, rr RR) {
	e, ok := c.entries[qname]
	if !ok {
		c._evict()
	}
	if e == nil {
		c.entries[qname] = make(map[RR]struct{})
		e = c.entries[qname]
	}
	e[rr] = struct{}{}
}

// addEntry adds an entry for qname to c.
// Not safe for concurrent usage.
func (c *cache) _addEntry(qname string) {
	_, ok := c.entries[qname]
	if !ok {
		c._evict()
		// For NXDOMAIN responses,
		// the cache entry is present, but nil.
		c.entries[qname] = nil
	}
}

// FIXME: better random cache eviction than Go’s random key guarantee?
// Not safe for concurrent usage.
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
func (c *cache) get(qname string) RRs {
	c.m.RLock()
	defer c.m.RUnlock()
	e, ok := c.entries[qname]
	if !ok {
		return nil
	}
	if len(e) == 0 {
		return emptyRRs
	}
	i := 0
	rrs := make(RRs, len(e))
	for rr := range e {
		rrs[i] = rr
		i++
	}
	return rrs
}
