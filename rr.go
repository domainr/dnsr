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
