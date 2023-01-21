#!/usr/bin/env bash

rm -v **/.DS_Store **/._.DS_Store

git add . && git commit -m "$(date)" && git push
