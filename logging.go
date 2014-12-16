package dnsr

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/miekg/dns"
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
	fmt.Fprintf(DebugLogger, "%s┌─── resolve(\"%s\", \"%s\", %d)\n",
		strings.Repeat("│   ", depth-1), qname, qtype, depth)
}

func logResolveEnd(qname string, qtype string, depth int, start time.Time) {
	if DebugLogger == nil {
		return
	}
	dur := time.Since(start)
	fmt.Fprintf(DebugLogger, "%s└─── %dms: resolve(\"%s\", \"%s\", %d)\n",
		strings.Repeat("│   ", depth-1), dur/time.Millisecond, qname, qtype, depth)
}

func logCNAME(depth int, cname string) {
	if DebugLogger == nil {
		return
	}
	fmt.Fprintf(DebugLogger, "%s│    CNAME: %s\n", strings.Repeat("│   ", depth-1), cname)
}

func logExchange(host string, qmsg *dns.Msg, depth int, start time.Time, err error) {
	if DebugLogger == nil {
		return
	}
	dur := time.Since(start)
	fmt.Fprintf(DebugLogger, "%s│    %dms: dig +norecurse @%s %s %s\n",
		strings.Repeat("│   ", depth-1), dur/time.Millisecond, host, qmsg.Question[0].Name, dns.TypeToString[qmsg.Question[0].Qtype])
	if err != nil {
		fmt.Fprintf(DebugLogger, "%s│    %dms: ERROR: %s\n",
			strings.Repeat("│   ", depth-1), dur/time.Millisecond, err.Error())
	}
}
