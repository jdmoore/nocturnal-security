#!/bin/bash

# autoban is a tool to parse through auth-log and ban IPs attempting to brute force ssh access
#
# WARNING: DO NOT USE THIS TOOL AS A PRIMARY DEFENSE. USE THIS TOOL AT YOUR OWN RISK
#
# This tool looks for IPs that have failed to log in 10 or more times (by default) and bans them using iptables
# 
# This tool requires superuser privileges
#
# Author: Joshua Moore <jdmoore1342@gmail.com>
# GitHub: <https://github.com/jdmoore>
# Last Edited: November 22, 2016
#
# This software is covered by the Apache2 license http://www.apache.org/licenses/LICENSE-2.0.txt

# [ Configurations ]
# Directory in which logs will be created
logdir="/var/log/autoban/"
# Maximum number of retries an IP can fail at root login before being banned, a la fail2ban <http://www.fail2ban.org/>
maxretry=10

# Confirm superuser privileges
if [ $(id -u) != "0" ]; then
	echo "User $USER does not have privileges to run this command"
	echo Exiting >> $logfile
	exit 1
fi 

# Generate log directory if necessary
if [ ! -d "$logdir" ]; then
	echo "Creating log directory: $logdir"
	mkdir /var/log/autoban/
fi

# Generate date stamp
stamp=$(date | awk '{print $2 "-" $3 "-" $6}')

# Set logfile path
logfile="${logdir}autoban-${stamp}"

# Date entry
date >> $logfile

# Get list of IPs that failed to log into root
grep "Failed.password.for" /var/log/auth.log | grep root | grep -v "message.repeated" | awk '{print $11}' | sort -u > /root/possibleOffenders.txt

# Read list of possible offenses
while read -r posOff
do
	# Count the number of times an IP failed to log into root
    accessCount=$(grep "Failed.password.for" /var/log/auth.log | grep $posOff | wc | awk '{print $1}')
    if (( "$accessCount" > 10 )); then
    	# Add IPs to the ban list if they've failed an unreasonable number of times
    	echo "Definite abuse: $posOff added to list for $accessCount attempts" >> $logfile
    	echo $posOff >> /root/tmp.txt
    else
    	# Otherwise, flag them
    	echo "Possible abuse: $posOff tried $accessCount times" >> $logfile
    fi
done <"/root/possibleOffenders.txt"


# Get list of IPs that failed to log into invalid accounts
grep "Failed.password.for" /var/log/auth.log | grep invalid | awk '{print $13}' | sort -u >> /root/tmp.txt

# Remove duplicates
sort -u /root/tmp.txt > /root/offendingIPs.txt

# Get list of banned IPs
banned=$(iptables -S | grep "j.DROP" | awk '{print $4}')

# Check offending IPs against the list of banned IPs
while read -r offender
do
    # Skip IPs that are already banned
    if [[ $banned == *"${offender}"* ]]; then
    	#echo "Match found for $offender in banned IPs" >> $logfile
    	continue
    fi
   
    # Ban any IP not already banned
    echo "NO MATCH for $offender. Banning..." >> $logfile
    iptables -A INPUT -s $offender -j DROP

done <"/root/offendingIPs.txt"

# Clean up
rm /root/tmp.txt
rm /root/possibleOffenders.txt
rm /root/offendingIPs.txt