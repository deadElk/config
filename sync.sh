#!/usr/bin/env bash

git add . && git commit -m "$(date)" && git push

rsync -havx --exclude ".*" ./go.* ./*.go root@10.5.58.18:/local/devel/config/
rynsc -n -hvx -r --del tmp/portal/ root@10.2.17.94:/local/jail/twid.domain.tld/.jail/local/www/portal.domain.tld/
rsync -hvx tmp/stage/openvpn/usr/local/etc/* root@10.5.58.22:/usr/local/etc/*
rsync -hvx -r --del tmp/stage/openvpn/usr/local/etc/openvpn/ root@10.5.58.22:/usr/local/etc/openvpn/
