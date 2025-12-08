package dnsr

import (
	"sync"
	"time"
)

type cache struct {
	capacity int
	expire   bool
	m        sync.RWMutex
	entries  map[string]entry
}

type entry map[RR]struct{}

const MinCacheCapacity = 1000

// newCache initializes and returns a new cache instance.
// Cache capacity defaults to MinCacheCapacity if <= 0.
func newCache(capacity int, expire bool) *cache {
	if capacity <= 0 {
		capacity = MinCacheCapacity
	}
	return &cache{
		capacity: capacity,
		entries:  make(map[string]entry),
		expire:   expire,
	}
}

// add adds 0 or more DNS records to the resolver cache for a specific
// domain name and record type. This ensures the cache entry exists, even
// if empty, for NXDOMAIN responses.
func (c *cache) add(qname string, rr RR) {
	c.m.Lock()
	defer c.m.Unlock()
	c._add(qname, rr)
}

// addNX adds an NXDOMAIN to the cache.
// Safe for concurrent usage.
func (c *cache) addNX(qname string) {
	c.m.Lock()
	defer c.m.Unlock()
	c._addEntry(qname)
}

// deleteNX removes an NXDOMAIN entry from the cache if it exists.
// This is used to remove NXDOMAIN entries from servers that are not authoritative for the queried domain.
// Safe for concurrent usage.
func (c *cache) deleteNX(qname string) {
	c.m.Lock()
	defer c.m.Unlock()
	if e, ok := c.entries[qname]; ok && e == nil {
		delete(c.entries, qname)
	}
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

// _addEntry adds an entry for qname to c.
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

	// First evict expired entries
	if c.expire {
		now := time.Now()
		for k, e := range c.entries {
			for rr := range e {
				if !rr.Expiry.IsZero() && rr.Expiry.Before(now) {
					delete(e, rr)
				}
			}
			if len(e) == 0 {
				delete(c.entries, k)
			}
			if len(c.entries) < c.capacity {
				return
			}
		}
	}

	// Then randomly evict entries
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
	if c.expire {
		now := time.Now()
		rrs := make(RRs, 0, len(e))
		for rr := range e {
			if rr.Expiry.IsZero() || rr.Expiry.After(now) {
				rrs = append(rrs, rr)
			}
		}
		return rrs
	} else {
		i := 0
		rrs := make(RRs, len(e))
		for rr := range e {
			rrs[i] = rr
			i++
		}
		return rrs
	}
}
