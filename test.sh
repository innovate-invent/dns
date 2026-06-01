#!/usr/bin/env bash

set -e -o pipefail

dpkg -s libunbound8 bind9-utils &>/dev/null || {
  apt update -y
  apt install -y libunbound8 bind9-utils
}

[[ -e /etc/ssl/certs/ssl-cert-snakeoil.pem ]] || apt install -y ssl-cert

./run_zonemaster.sh &
cd ../../
trap 'kill %%' EXIT

karma start --single-run --browsers ChromeHeadless karma.conf.cjs