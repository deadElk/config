#!/usr/bin/env bash

#_name=$(< ./.git/description)
_name="config"

~/go/go1.18rc1/bin/go build -ldflags="-s -w" -trimpath -o "${_name}" ./*.go || /local/devel/go/bin/go build -ldflags="-s -w" -trimpath -o "${_name}" ./*.go || exit 1
