# dnsr

Iterative DNS resolver for Go.

## Notes

Each resolver (core, cache, authority) implements the `Resolver` interface:

```go
type Resolver interface {
	Resolve(qname string, qtype dns.Type) (*dns.Msg, error)
}
```

The `coreResolver` first checks its cache, then the authority for a given name:

```go
type coreResolver struct {
  cache Resolver
}
```

An `authorityResolver` resolves via the authority (NS) for a given name:

```go
type authorityResolver struct {
  name string
  cache Resolver
}
```
