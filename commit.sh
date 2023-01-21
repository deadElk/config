#!/usr/bin/env bash

find . -type f \( -name ".DS_Store" -o -name "._.DS_Store" \) -delete -print

git add . && git commit -m "$(date)" && git push
