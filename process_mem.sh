#!/bin/bash

if [ $# -ne 2 ]; then
    echo "Usage: $0 <pid> <output_file>"
    exit 1
fi

pid=$1
output_file=$2

while true; do
    current_time=$(date "+%Y-%m-%d %H:%M:%S")
    echo "Memory content for process $pid at $current_time" >> "$output_file"
    echo "Memory content for process $pid at $(date)" >> "$output_file"
    cat /proc/$pid/maps >> "$output_file"
    echo "----------------------------------------" >> "$output_file"
    sleep 1
done
