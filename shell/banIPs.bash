#!/bin/bash
input=$1

while read -r offender
do
    echo "banning $offender"
    iptables -A INPUT -s $var -j DROP
done <"$input"
