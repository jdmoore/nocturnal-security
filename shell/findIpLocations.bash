#!/bin/bash
input=$1

while read -r line
do
    ip=$(echo $line | awk '{print $1}')
    #echo $ip
    country=$(whois $ip | grep [C,c]ountry | awk '{print $2}')
    city=$(whois $ip | grep [C,c]ity | awk '{print $2, $3}')
    #address=$(whois $ip | grep [A,a]ddress)
    echo $ip $country $city
done <"$input"

