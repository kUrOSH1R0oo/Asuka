#!/bin/bash

if [ "$#" -ne 2 ]; then
	echo "Usage: $0 <ip> <port>"
	exit 1
fi

IP="$1"
PORT="$2"

ssh -R 80:"$IP":"$PORT" serveo.net
