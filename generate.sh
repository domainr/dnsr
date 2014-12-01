#!/usr/bin/env sh
PFX=rootbindata
DIR=$TMPDIR/$PFX
mkdir -p $DIR
curl -o $DIR/root.zone http://www.internic.net/domain/root.zone
go-bindata -pkg=dnsr -prefix=$DIR -o=root.go $DIR
