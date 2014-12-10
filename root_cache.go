package dnsr

import (
	"strings"

	"github.com/miekg/dns"
)

//go:generate sh generate.sh

var (
	rootCache *Resolver
)

func init() {
	rootCache = New(strings.Count(root, "\n"))
	for t := range dns.ParseZone(strings.NewReader(root), "", "") {
		if t.Error == nil {
			rootCache.saveDNSRR(t.RR)
		}
	}
}
