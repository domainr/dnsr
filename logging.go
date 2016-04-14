package dnsr

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/domainr/dns"
)

var (
	DebugLogger io.Writer
)

func logMaxRecursion(qname string, qtype string, depth int) {
	if DebugLogger == nil {
		return
	}
	fmt.Fprintf(DebugLogger, "%s Error: MAX RECURSION @ %s %s %d\n",
		strings.Repeat("│   ", depth-1), qname, qtype, depth)
}

func logResolveStart(qname string, qtype string, depth int) {
	if DebugLogger == nil {
		return
	}
	fmt.Fprintf(DebugLogger, "%s╭─── resolve(\"%s\", \"%s\", %d)\n",
		strings.Repeat("│   ", depth-1), qname, qtype, depth)
}

func logResolveEnd(qname string, qtype string, rrs RRs, depth int, start time.Time, err error) {
	if DebugLogger == nil {
		return
	}
	dur := time.Since(start)
	fmt.Fprintf(DebugLogger, "%s╰─── %dms: resolve(\"%s\", \"%s\", %d)",
		strings.Repeat("│   ", depth-1), dur/time.Millisecond, qname, qtype, depth)
	if rrs == nil {
		fmt.Fprintf(DebugLogger, " # rrs = nil ")
	} else if len(rrs) > 0 {
		fmt.Fprintf(DebugLogger, " # [%d]RR = ", len(rrs))
		for _, rr := range rrs {
			fmt.Fprintf(DebugLogger, "%s:%s ", rr.Type, rr.Value)
		}
	}
	if err != nil {
		fmt.Fprintf(DebugLogger, " # ERROR: %s", err)
	}
	fmt.Fprintf(DebugLogger, "\n")
}

func logCNAME(cname string, depth int) {
	if DebugLogger == nil {
		return
	}
	fmt.Fprintf(DebugLogger, "%s│    CNAME: %s\n", strings.Repeat("│   ", depth-1), cname)
}

func logExchange(host string, qmsg *dns.Msg, rmsg *dns.Msg, depth int, start time.Time, err error) {
	if DebugLogger == nil {
		return
	}
	dur := time.Since(start)
	fmt.Fprintf(DebugLogger, "%s│    %dms: dig +norecurse @%s %s %s ",
		strings.Repeat("│   ", depth-1), dur/time.Millisecond, host, qmsg.Question[0].Name, dns.TypeToString[qmsg.Question[0].Qtype])
	if rmsg != nil {
		fmt.Fprintf(DebugLogger, " # rmsg: %s Answer: %d NS: %d Extra: %d",
			dns.RcodeToString[rmsg.Rcode], len(rmsg.Answer), len(rmsg.Ns), len(rmsg.Extra))
	}
	if err != nil {
		fmt.Fprintf(DebugLogger, " # ERROR: %s", err.Error())
	}
	fmt.Fprintf(DebugLogger, "\n")
}
