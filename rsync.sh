#!/usr/bin/env bash

rsync -hvx -lr ~/patch/tmp/ ./tmp/

. ./commit.sh

rsync -hvx -lr --del tmp/portal/ root@10.2.17.94:/local/jail/twid.domain.tld/.jail/local/www/portal.domain.tld/
rsync -hvx -lr tmp/stage/openvpn/usr/local/etc/ root@10.5.58.22:/usr/local/etc/
rsync -hvx -lr --del tmp/stage/openvpn/usr/local/etc/openvpn/ root@10.5.58.22:/usr/local/etc/openvpn/
