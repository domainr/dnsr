# dnsr

[![build status](https://img.shields.io/circleci/project/domainr/dnsr/master.svg)](https://circleci.com/gh/domainr/dnsr)
[![godoc](http://img.shields.io/badge/docs-GoDoc-blue.svg)](https://godoc.org/github.com/domainr/dnsr)

`go get github.com/domainr/dnsr`

Iterative DNS resolver for Go.

The `Resolve` method on `dnsr.Resolver` queries DNS for given name and type (`A`, `NS`, `CNAME`, etc.). The resolver caches responses for queries, and liberally (aggressively?) returns DNS records for a given name, not waiting for slow or broken name servers.

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

© 2014–2015 nb.io, LLC
