#!/usr/bin/env bash

set -e -o pipefail

dpkg -s libunbound8 bind9-utils &>/dev/null || {
  apt update -y
  apt install -y libunbound8 bind9-utils
}

[[ -e /etc/ssl/certs/ssl-cert-snakeoil.pem ]] || apt install -y ssl-cert

iface="${INTERFACE:-templo}"

#ip a show "$iface" | grep -q '127.0.0.1/8' ||
#  sudo ip addr add "127.0.0.1/8" dev "$iface"
#
#ip a show "$iface" | grep -q 'fda1:b2:c3:0:127::1/80' ||
#  sudo ip addr add "fda1:b2:c3::127:0:0:1/80" dev "$iface"

trap "ip link delete '$iface'" EXIT
ip link add name "$iface" type dummy

# Read every line in the data file (markdown)
while IFS= read -r line; do
  # Get IP addresses without prefix (e.g. /24)
  if [[ $line =~ ^\|\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\ +\| ]]; then
    ip_address=${BASH_REMATCH[1]}
    # Add address for both IPv4 and IPv6
    ip addr add "${ip_address}/32" dev "$iface"
    ip addr add "fda1:b2:c3::$(tr '.' ':' <<<$ip_address)/128" dev "$iface"
  fi
done < "zonemaster/test-zone-data/address-plan.md"

# Add signed root and xa IP
for ip_address in "127.1.0.3" "127.2.0.15" "127.4.1.1"; do
  ip addr add "${ip_address}/32" dev "$iface"
  ip addr add "fda1:b2:c3::$(tr '.' ':' <<<$ip_address)/128" dev "$iface"
done

for i in 5 7 8 10 13 14; do
  ip addr add "127.4.0.${i}/32" dev "$iface"
  ip addr add "fda1:b2:c3::127:4:0:${i}/128" dev "$iface"
done

cd zonemaster/test-zone-data
../../coredns -conf ../../doh.cfg