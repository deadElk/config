#!/usr/bin/env bash

#_name=$(< ./.git/description)
_name="config"

go build -ldflags="-s -w" -trimpath -o "${_name}" ./*.go || exit 1
