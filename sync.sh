#!/usr/bin/env bash

git add . && git commit -m "$(date)" && git push

rsync -havx --exclude ".*" ./go.* ./*.go root@10.5.58.18:/local/devel/config/
rsync -havx --del tmp/stage/openvpn/usr/local/etc/openvpn/ root@10.5.58.22:/usr/local/etc/openvpn/
