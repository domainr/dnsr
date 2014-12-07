# dnsr [![GoDoc](https://godoc.org/github.com/domainr/dnsr?status.png)](https://godoc.org/github.com/domainr/dnsr) ![Project Status](http://img.shields.io/badge/status-development-red.svg)

`go get github.com/domainr/dnsr`

Iterative DNS resolver for Go.

The `Resolve` method on `dnsr.Resolver` queries DNS for given name and type (`A`, `NS`, `CNAME`, etc.). The resolver caches responses for queries, and liberally (aggressively?) returns DNS records for a given name, not waiting for slow or broken name servers. It runs each query in 1 or more goroutine internally, and returns results in a slice of `*dnsr.RR`.

This code leans heavily on [Miek Gieben’s](https://github.com/miekg) excellent [dns library for Go](https://github.com/miekg/dns).

## Example

```go
package main

import (
  "fmt"
  "github.com/domainr/dnsr"
)

func main() {
  r := dnsr.New(10000)
  for _, rr := range r.Resolve("google.com", "TXT") {
    fmt.Println(rr.String())
  }
}
```

## Development

Run `go generate` in Go 1.4+ to refresh the [root zone hint file](http://www.internic.net/domain/named.root). Pull requests welcome.

## Copyright

© 2014 nb.io, LLC
