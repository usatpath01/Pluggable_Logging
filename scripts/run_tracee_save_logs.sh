#!/bin/bash

# List of remote servers and their respective usernames
servers=(
      "username@XX.X.XX.XXX"    
      "username@XX.X.XX.XXX"
)

# Remote server to copy log files to
remote_server="username@XX.X.XX.XXX"
remote_path="/Pluggable_Logging/Tracee_Logs/"

# Function to get username from server string
get_username() {
    echo "$1" | cut -d '@' -f 1
}

# Loop over each server and execute the commands via SSH
for server in "${servers[@]}"
do
    username=$(get_username "$server")
    log_dir="/home/$username/Pluggable_Logging/Tracee_Logs"
    docker_logs_command="docker logs tracee_\$(hostname) &> ${log_dir}/tracee_\$(hostname)_24July.txt"
    #docker_kill_command="docker kill tracee_\$(hostname)"

    echo "Running commands on $server"
    ssh -o StrictHostKeyChecking=no "$server" "cd ${log_dir} && $docker_logs_command"
    scp "$server:${log_dir}/tracee_\$(hostname)_24July.txt" "${remote_server}:${remote_path}/${log_file}"
done
