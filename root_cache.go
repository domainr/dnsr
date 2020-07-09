package dnsr

import (
	"strings"

	"github.com/miekg/dns"
)

//go:generate sh generate.sh

var (
	rootCache *cache
)

func init() {
	rootCache = newCache(strings.Count(root, "\n"), false)
	zp := dns.NewZoneParser(strings.NewReader(root), "", "")

	for drr, ok := zp.Next(); ok; drr, ok = zp.Next() {
		rr, ok := convertRR(drr, false)
		if ok {
			rootCache.add(rr.Name, rr)
		}
	}

	if err := zp.Err(); err != nil {
		return
	}
}
