package main

import (
	"flag"
	"os"
	"strings"
	"time"

	"code.google.com/p/go.net/idna"
	"github.com/domainr/dnsr"
	"github.com/miekg/dns"
	"github.com/wsxiaoys/terminal/color"
)

const (
	timeout = 2000 * time.Millisecond
)

var (
	verbose   bool
	cache     = make(map[dns.Question][]dns.RR)
	dnsClient = &dns.Client{
		Net:          "udp",
		DialTimeout:  timeout,
		ReadTimeout:  timeout,
		WriteTimeout: timeout,
	}
	resolver = dnsr.New(10000)
)

func init() {
	parseRoot()

	flag.BoolVar(
		&verbose,
		"v",
		false,
		"print verbose info to the console",
	)

	dnsr.Verbose = verbose
}

func logV(fmt string, args ...interface{}) {
	if !verbose {
		return
	}
	color.Printf(fmt, args...)
}

func main() {
	flag.Usage = func() {
		color.Fprintf(os.Stderr, "Usage: %s [arguments] <name> [type]\n\nAvailable arguments:\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}
	flag.Parse()
	rrType := "A"
	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
	} else if len(args) > 1 {
		rrType, args = args[len(args)-1], args[:len(args)-1]
	}
	for _, name := range args {
		query(name, rrType)
	}
}

func query(name, rrType string) {
	nameIDNA, err := idna.ToASCII(name)
	if err != nil {
		color.Fprintf(os.Stderr, "Invalid IDN domain name: %s\n", name)
		os.Exit(1)
	}

	q := dns.Question{toLowerFQDN(nameIDNA), dns.StringToType[strings.ToUpper(rrType)], dns.ClassINET}
	// rrs := exchange(q)
	rrs := resolver.Resolve(q)

	logV("@{g}\n;; RESULTS:\n")
	for _, rr := range rrs {
		color.Printf("@{g}%s\n", rr.String())
	}

	if rrs == nil {
		color.Printf("@{y};; NIL   %s\n", name)
	} else if len(rrs) > 0 {
		color.Printf("@{g};; TRUE  %s\n", name)
	} else {
		color.Printf("@{r};; FALSE %s\n", name)
	}
}

func cacheGet(q dns.Question) []dns.RR {
	return cache[q]
}

func cacheSet(rrs ...dns.RR) {
	for _, rr := range rrs {
		h := rr.Header()
		h.Name = toLowerFQDN(h.Name)
		q := dns.Question{strings.ToLower(h.Name), h.Rrtype, h.Class}
		cacheInsert(q, rr)
	}
}

func cacheInsert(q dns.Question, rr dns.RR) {
	for _, rr2 := range cache[q] {
		if rr2.String() == rr.String() {
			return
		}
	}
	cache[q] = append(cache[q], rr)
}

func toLowerFQDN(name string) string {
	return dns.Fqdn(strings.ToLower(name))
}

func parent(name string) (string, bool) {
	labels := dns.SplitDomainName(name)
	if labels == nil {
		return "", false
	}
	return toLowerFQDN(strings.Join(labels[1:], ".")), true
}

func exchange(q dns.Question) []dns.RR {
	defer logV("@{};; QUESTION:\n%s\n\n\n", q.String())

	q.Name = toLowerFQDN(q.Name)

	// Check cache
	rrs := cacheGet(q)
	if rrs != nil {
		logV("@{.};; CACHED:\n")
		for _, rr := range rrs {
			logV("@{.}%s\n", rr.String())
		}
		return rrs
	}

	// Find authorities (nameservers)
	nsName := q.Name
	if q.Qtype == dns.TypeNS {
		var ok bool
		// Query parent for NS queries
		nsName, ok = parent(q.Name)
		if !ok {
			logV("ERROR: tried to get parent of .\n")
			return nil
		}
	}
	nsQ := dns.Question{nsName, dns.TypeNS, q.Qclass}
	nses := exchange(nsQ)
	if nses == nil {
		logV("@{r};; RESPONSE: no NS records found for %s\n", nsQ.Name)
		return nil
	}

	// Iterate through nameservers
	for _, rr := range nses {
		// Get authority’s A record
		ns := rr.(*dns.NS)
		ipQ := dns.Question{ns.Ns, dns.TypeA, q.Qclass}
		ips := exchange(ipQ)
		if ips == nil {
			logV("@{r};; RESPONSE: no A records found for %s\n", ipQ.Name)
			continue
		}

		// Iterate through IP addresses
		for _, rr := range ips {
			qMsg := &dns.Msg{}
			qMsg.SetQuestion(q.Name, q.Qtype)
			qMsg.MsgHdr.RecursionDesired = false
			ip := rr.(*dns.A)
			addr := ip.A.String() + ":53"
			rMsg, _, err := dnsClient.Exchange(qMsg, addr)
			if err != nil {
				logV("@{r};; ERROR: %s\n", err.Error())
				continue
			}

			// FIXME: cache NXDOMAIN responses responsibly
			if rMsg.Rcode == dns.RcodeNameError {
				cache[q] = make([]dns.RR, 0)
			}

			// Log responses
			logV("@{c};; ANSWER:\n")
			for _, rr := range rMsg.Answer {
				logV("@{c}%s\n", rr.String())
			}
			logV("@{c}\n;; AUTHORITY:\n")
			for _, rr := range rMsg.Ns {
				logV("@{c}%s\n", rr.String())
			}
			logV("@{c}\n;; EXTRA:\n")
			for _, rr := range rMsg.Extra {
				logV("@{c}%s\n", rr.String())
			}

			// Cache responses
			cacheSet(rMsg.Answer...)
			cacheSet(rMsg.Ns...)
			cacheSet(rMsg.Extra...)

			// Check cache again
			rrs := cacheGet(q)
			if rrs != nil {
				return rrs
			}

			break
		}

		break
	}

	// Only check CNAMES for A and AAAA questions
	if q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA {
		return nil
	}

	// Check cache for CNAMEs
	cQ := dns.Question{q.Name, dns.TypeCNAME, q.Qclass}
	rrs = cacheGet(cQ)
	if rrs != nil {
		// Iterate through CNAMEs
		for _, rr := range rrs {

			// Get CNAME target
			cn := rr.(*dns.CNAME)
			cQ2 := dns.Question{cn.Target, q.Qtype, q.Qclass}
			cns := exchange(cQ2)
			if cns == nil {
				logV("@{r};; RESPONSE: no records found for CNAME %s\n", cQ2.Name)
				continue
			}

			return cns
		}
	}

	return nil
}

/*

STEPS
check cache for {name, type, class}; if found, return
find authorities for {name} // RECURSIVE
get A records for authorities // RECURSIVE
query authorities’ A records for {name, type, class}
if authority responds with a CNAME for an A question, resolve CNAMEs // RECURSIVE

QUERIES
blueoven.com. A
blueoven.com. NS
com. NS
. NS

*/

func parseRoot() {
	tokens := dns.ParseZone(strings.NewReader(root), "", "")
	for t := range tokens {
		if t.Error != nil {
			continue
		}
		cacheSet(t.RR)
	}
}

var root = `
;       This file holds the information on root name servers needed to
;       initialize cache of Internet domain name servers
;       (e.g. reference this file in the "cache  .  <file>"
;       configuration file of BIND domain name servers).
;
;       This file is made available by InterNIC 
;       under anonymous FTP as
;           file                /domain/named.cache
;           on server           FTP.INTERNIC.NET
;       -OR-                    RS.INTERNIC.NET
;
;       last update:    June 2, 2014
;       related version of root zone:   2014060201
;
; formerly NS.INTERNIC.NET
;
.                        3600000  IN  NS    A.ROOT-SERVERS.NET.
A.ROOT-SERVERS.NET.      3600000      A     198.41.0.4
A.ROOT-SERVERS.NET.      3600000      AAAA  2001:503:BA3E::2:30
;
; FORMERLY NS1.ISI.EDU
;
.                        3600000      NS    B.ROOT-SERVERS.NET.
B.ROOT-SERVERS.NET.      3600000      A     192.228.79.201
B.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:84::B
;
; FORMERLY C.PSI.NET
;
.                        3600000      NS    C.ROOT-SERVERS.NET.
C.ROOT-SERVERS.NET.      3600000      A     192.33.4.12
C.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:2::C
;
; FORMERLY TERP.UMD.EDU
;
.                        3600000      NS    D.ROOT-SERVERS.NET.
D.ROOT-SERVERS.NET.      3600000      A     199.7.91.13
D.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:2D::D
;
; FORMERLY NS.NASA.GOV
;
.                        3600000      NS    E.ROOT-SERVERS.NET.
E.ROOT-SERVERS.NET.      3600000      A     192.203.230.10
;
; FORMERLY NS.ISC.ORG
;
.                        3600000      NS    F.ROOT-SERVERS.NET.
F.ROOT-SERVERS.NET.      3600000      A     192.5.5.241
F.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:2F::F
;
; FORMERLY NS.NIC.DDN.MIL
;
.                        3600000      NS    G.ROOT-SERVERS.NET.
G.ROOT-SERVERS.NET.      3600000      A     192.112.36.4
;
; FORMERLY AOS.ARL.ARMY.MIL
;
.                        3600000      NS    H.ROOT-SERVERS.NET.
H.ROOT-SERVERS.NET.      3600000      A     128.63.2.53
H.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:1::803F:235
;
; FORMERLY NIC.NORDU.NET
;
.                        3600000      NS    I.ROOT-SERVERS.NET.
I.ROOT-SERVERS.NET.      3600000      A     192.36.148.17
I.ROOT-SERVERS.NET.      3600000      AAAA  2001:7FE::53
;
; OPERATED BY VERISIGN, INC.
;
.                        3600000      NS    J.ROOT-SERVERS.NET.
J.ROOT-SERVERS.NET.      3600000      A     192.58.128.30
J.ROOT-SERVERS.NET.      3600000      AAAA  2001:503:C27::2:30
;
; OPERATED BY RIPE NCC
;
.                        3600000      NS    K.ROOT-SERVERS.NET.
K.ROOT-SERVERS.NET.      3600000      A     193.0.14.129
K.ROOT-SERVERS.NET.      3600000      AAAA  2001:7FD::1
;
; OPERATED BY ICANN
;
.                        3600000      NS    L.ROOT-SERVERS.NET.
L.ROOT-SERVERS.NET.      3600000      A     199.7.83.42
L.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:3::42
;
; OPERATED BY WIDE
;
.                        3600000      NS    M.ROOT-SERVERS.NET.
M.ROOT-SERVERS.NET.      3600000      A     202.12.27.33
M.ROOT-SERVERS.NET.      3600000      AAAA  2001:DC3::35
; End of File
`
