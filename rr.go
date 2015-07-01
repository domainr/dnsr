package dnsr

import (
	"strings"

	"github.com/miekg/dns"
)

// RR represents a DNS resource record.
type RR struct {
	Name  string
	Type  string
	Value string
}

type RRs []RR

// emptyRRs is an empty, non-nil slice of RRs.
// It is used to save allocations at runtime.
var emptyRRs = RRs{}

// ICANN specifies that DNS servers should return the special value 127.0.53.53
// for A record queries of TLDs that have recently entered the root zone,
// that have a high likelyhood of colliding with private DNS names.
// The record returned is a notices to network administrators to adjust their
// DNS configuration.
// https://www.icann.org/resources/pages/name-collision-2013-12-06-en#127.0.53.53
const NameCollision = "127.0.53.53"

// String returns a string representation of an RR in zone-file format.
func (rr *RR) String() string {
	return rr.Name + "\t      3600\tIN\t" + rr.Type + "\t" + rr.Value
}

// convertRR converts a dns.RR to an RR.
func convertRR(drr dns.RR) (RR, bool) {
	h := drr.Header()
	rr := RR{
		Name: toLowerFQDN(h.Name),
		Type: dns.TypeToString[h.Rrtype],
	}
	switch t := drr.(type) {
	// case *dns.SOA:
	// 	rr.Value = toLowerFQDN(t.String())
	case *dns.NS:
		rr.Value = toLowerFQDN(t.Ns)
	case *dns.CNAME:
		rr.Value = toLowerFQDN(t.Target)
	case *dns.A:
		rr.Value = t.A.String()
	case *dns.AAAA:
		rr.Value = t.AAAA.String()
	case *dns.TXT:
		rr.Value = strings.Join(t.Txt, "\t")
	default:
		return rr, false
	}
	return rr, true
}
