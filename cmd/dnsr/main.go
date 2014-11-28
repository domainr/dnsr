package main

import (
	"flag"
	"os"
	"strings"
	"sync"
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
	verbose  bool
	resolver = dnsr.New(10000)
)

func init() {
	flag.BoolVar(
		&verbose,
		"v",
		false,
		"print verbose info to the console",
	)
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
	var wg sync.WaitGroup
	start := time.Now()
	for _, name := range args {
		wg.Add(1)
		go func(name string, rrType string) {
			query(name, rrType)
			wg.Done()
		}(name, rrType)
	}
	wg.Wait()
	logV("\n@{w};; Total elapsed: %s\n", time.Since(start).String())
}

func query(name, rrType string) {
	start := time.Now()
	qname, err := idna.ToASCII(name)
	if err != nil {
		color.Fprintf(os.Stderr, "Invalid IDN domain name: %s\n", name)
		os.Exit(1)
	}
	qtype := dns.StringToType[strings.ToUpper(rrType)]

	// q := dns.Question{qname, qtype, dns.ClassINET}
	// rrs := exchange(q)
	rrc := resolver.Resolve(qname, qtype)
	rrs := []dns.RR{}
	for rr := range rrc {
		if rr == nil {
			logV("@{r}\n;; NIL RR!\n")
			continue
		}
		rrs = append(rrs, rr)
	}

	color.Printf("\n")
	if len(rrs) > 0 {
		color.Printf("@{g};; RESULTS:\n")
	}
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

	logV("@{.w};; Elapsed: %s\n", time.Since(start).String())
}
