# dnsr

Iterative DNS resolver for Go.

## Design

Resolver that emits a slice of results for a given name and type (A, NS, CNAME, etc.). The resolver caches responses for queries.

### Layers

- Cache
- Resolve addresses for names (A, AAAA)
- Resolve CNAMEs
- Find NS records (authority) for names
- Interrogate another name server (this layer will cache)

### Where to cache?

- Cache at outer level?
- Cache immediately around DNS exchange?
- Cache at every layer?


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
