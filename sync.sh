#!/usr/bin/env bash

git add . && git commit -m "$(date)" && git push

rsync -havx --del --exclude ".*" ./go.* ./*.go ./etc root@10.5.58.18:/local/devel/config/
