#!/bin/sh

mkdir -p /dev/net
mknod /dev/net/tun c 10 200

socat TCP-LISTEN:8080,fork UNIX-CONNECT:/tmp/pysim/.Pysim &

exec $@