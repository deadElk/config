#!/usr/bin/env bash

git add . && git commit -m "$(date)" && git push

rsync -havx --exclude ".*" ./go.* ./*.go root@10.5.58.18:/local/devel/config/
