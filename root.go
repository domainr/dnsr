package dnsr

import (
	"strings"

	_ "embed"

	"github.com/miekg/dns"
)

//go:generate curl -O https://www.internic.net/domain/named.root

//go:embed named.root
var root string

var rootCache *cache

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
		panic(err)
	}
}
