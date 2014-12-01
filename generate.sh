#!/usr/bin/env sh
echo "package dnsr\n\nvar root = \`" > root.go
curl http://www.internic.net/domain/named.root >> root.go
echo "\`" >> root.go
