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

// emptyRRs is an empty, non-nil slice of RRs.
// It is used to save allocations at runtime.
var emptyRRs = []*RR{}

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

func convertRR(drr dns.RR) *RR {
	switch t := drr.(type) {
	case *dns.NS:
		return &RR{toLowerFQDN(t.Hdr.Name), dns.TypeToString[t.Hdr.Rrtype], toLowerFQDN(t.Ns)}
	case *dns.CNAME:
		return &RR{toLowerFQDN(t.Hdr.Name), dns.TypeToString[t.Hdr.Rrtype], toLowerFQDN(t.Target)}
	case *dns.A:
		return &RR{toLowerFQDN(t.Hdr.Name), dns.TypeToString[t.Hdr.Rrtype], t.A.String()}
	case *dns.AAAA:
		return &RR{toLowerFQDN(t.Hdr.Name), dns.TypeToString[t.Hdr.Rrtype], t.AAAA.String()}
	case *dns.TXT:
		return &RR{toLowerFQDN(t.Hdr.Name), dns.TypeToString[t.Hdr.Rrtype], strings.Join(t.Txt, "\t")}
	default:
		// fmt.Printf("%s\n", drr.String())
	}
	return nil
}
