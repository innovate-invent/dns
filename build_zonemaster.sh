#!/usr/bin/env bash

find $PWD/zonemaster/ -name '*.zone' |
while read -r path; do
  named-compilezone -f text -F raw -i none \
  -k ignore -m ignore -M ignore -n ignore -r ignore -S ignore -W ignore \
  -w "$(dirname "$path")" -o "${path}.raw" "$(basename "$path" .zone)" "$path" &
done

wait