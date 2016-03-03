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
// If the RR is not a type that this package uses,
// it returns an undefined RR and false.
func convertRR(drr dns.RR) (RR, bool) {
	switch t := drr.(type) {
	case *dns.SOA:
		return RR{toLowerFQDN(t.Hdr.Name), "SOA", toLowerFQDN(t.Ns)}, true
	case *dns.NS:
		return RR{toLowerFQDN(t.Hdr.Name), "NS", toLowerFQDN(t.Ns)}, true
	case *dns.CNAME:
		return RR{toLowerFQDN(t.Hdr.Name), "CNAME", toLowerFQDN(t.Target)}, true
	case *dns.A:
		return RR{toLowerFQDN(t.Hdr.Name), "A", t.A.String()}, true
	case *dns.AAAA:
		return RR{toLowerFQDN(t.Hdr.Name), "AAAA", t.AAAA.String()}, true
	case *dns.TXT:
		return RR{toLowerFQDN(t.Hdr.Name), "TXT", strings.Join(t.Txt, "\t")}, true
	}
	return RR{}, false
}
