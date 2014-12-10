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
	rootCache = newCache(strings.Count(root, "\n"))
	for t := range dns.ParseZone(strings.NewReader(root), "", "") {
		if t.Error != nil {
			continue
		}
		if rr := convertRR(t.RR); rr != nil {
			rootCache.add(rr.Name, rr)
		}
	}
}
