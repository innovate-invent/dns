#!/usr/bin/env bash

set -eo pipefail

cd testdata

function genzone() {
    local zone="$1"
    local alg="$2"
    local zsk="$(dnssec-keygen -a $alg -b 2048 -n ZONE "$zone" 2>/dev/null)"
    local ksk="$(dnssec-keygen -f KSK -a $alg -b 2048 -n ZONE "$zone" 2>/dev/null)"
    echo "Generating $1"
    mv "$zsk.key" "${zone}zsk.key"
    mv "$zsk.private" "${zone}zsk.private"
    mv "$ksk.key" "${zone}ksk.key"
    mv "$ksk.private" "${zone}ksk.private"
    dnssec-signzone $3 -N INCREMENT -o "${zone}" -f "${zone}zone.signed" -t "$zone"zone "${zone}zsk.private" "${zone}ksk.private"
    ../convert_zonemaster.js ../zonefile.sabnf "${zone}zone.signed" ../zone_template.hb > "${zone}zone.trimmed"
    ../convert_zonemaster.js ../zonefile.sabnf "${zone}zone.signed" ../coredns_template.hb > "${zone}coredns.cfg"
    rm "${zone}ksk.private" "${zone}ksk.key" "${zone}zsk.key" "${zone}zsk.private" "dsset-$zone" "${zone}zone.signed"
}

tsx ../generate_expected.ts > example.xa.zone

sed 's/127.2.0.11/127.2.0.15/;s/fda1:b2:c3::127:2:0:11/fda1:b2:c3::127:2:0:15/;s/ns2 \+A \+127.2.0.12/\$INCLUDE xa.zsk.key/;s/ns2 \+AAAA \+fda1:b2:c3::127:2:0:12/\$INCLUDE xa.ksk.key/' ../zonemaster/test-zone-data/COMMON/xa > xa.zone

head -n4 example.xa.zone >> xa.zone

for zone in "." "xa."; do
  genzone "$zone" RSASHA256 "-3 C0DECAFE -A"
done

for i in 5 7 8 10 13 14; do
  ALG=$i envsubst '$ALG' <dnssec-alg.xa.zone.tmpl >dnssec-alg$i.xa.zone
done

# RSASHA1 Alg5
genzone "dnssec-alg5.xa." RSASHA1
# NSEC3RSASHA1 Alg7
genzone "dnssec-alg7.xa." NSEC3RSASHA1 "-3 C0DECAFE -A"
# RSASHA256 Alg8
genzone "dnssec-alg8.xa." RSASHA256
# RSASHA512 Alg10
genzone "dnssec-alg10.xa." RSASHA512
# ECDSAP256SHA256 Alg13
genzone "dnssec-alg13.xa." ECDSAP256SHA256
# ECDSAP384SHA384 Alg14
genzone "dnssec-alg14.xa." ECDSAP384SHA384
# ED25519
# ED448
# DH