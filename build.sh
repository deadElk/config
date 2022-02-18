#!/usr/bin/env bash

_name=$(< ./.git/description)

~/go/go1.18beta2/bin/go build -ldflags="-s -w" -trimpath -o "${_name}" ./main.go || exit 1
