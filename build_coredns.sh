#!/usr/bin/env bash

set -ex

podman run --rm -v .:/data --entrypoint bash -i docker.io/golang <<EOF
set -ex
apt update -y
apt install -y libunbound-dev libcap2-bin git

git clone https://github.com/coredns/coredns.git coredns
cd coredns
echo "unbound:github.com/coredns/unbound" >> plugin.cfg
git apply /data/Add_template_and_acl_to_EnableChaos.patch

go get github.com/coredns/unbound
go generate
CGO_ENABLED=1 make
setcap cap_net_bind_service=+ep coredns

cp coredns /data/coredns
EOF