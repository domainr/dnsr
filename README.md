# dnsr

[![build status](https://img.shields.io/github/workflow/status/domainr/dnsr/Go.svg)](https://github.com/domainr/dnsr/actions)
[![pkg.go.dev](https://img.shields.io/badge/docs-pkg.go.dev-blue.svg)](https://pkg.go.dev/github.com/domainr/dnsr)

Iterative DNS resolver for [Go](https://golang.org/).

The `Resolve` method on `dnsr.Resolver` queries DNS for given name and type (`A`, `NS`, `CNAME`, etc.). The resolver caches responses for queries, and liberally (aggressively?) returns DNS records for a given name, not waiting for slow or broken name servers.

This code leans heavily on [Miek Gieben’s](https://github.com/miekg) excellent [DNS library](https://github.com/miekg/dns),
 and is currently in production use at [Domainr](https://domainr.com/).

## Install

`go get github.com/domainr/dnsr`

## Usage

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

Or construct with `dnsr.NewExpiring()` to expire cache entries based on TTL.

[Documentation](https://pkg.go.dev/github.com/domainr/dnsr)

## Development

Run `go generate` in Go 1.4+ to refresh the [root zone hint file](http://www.internic.net/domain/named.root). Pull requests welcome.

## Copyright

© nb.io, LLC
