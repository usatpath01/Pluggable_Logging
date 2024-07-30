#!/bin/bash

# List of worker nodes with usernames, IPs, and their corresponding folder paths
declare -A systems
systems=(
    ["usename@XX.X.XX.XXX"]="/Pluggable_Logging"
    ["username@XX.X.XX.XXX"]="/Pluggable_Logging"
)

# Command to run docker-compose
docker_compose_cmd="docker-compose up xplog_agent -d"

for system in "${!systems[@]}"; do
    remote_folder="${systems[$system]}"
    echo "Running docker-compose up $system in folder $remote_folder"
    ssh "$system" "cd $remote_folder && $docker_compose_cmd"
done
