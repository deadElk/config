#!/usr/bin/env bash

git add . && git commit -m "$(date)" && git push

rsync -havx --exclude ".*" --del /Volumes/devel/config/ root@10.240.48.104:/local/devel/config/
rsync -havx --exclude ".*" /Volumes/devel/config/*.go root@10.2.58.18:/local/devel/config/
