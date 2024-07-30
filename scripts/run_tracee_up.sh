#!/bin/bash

# List of remote worker node servers
servers=(
      "username@XX.X.XX.XXX"    
      "username@XX.X.XX.XXX"
)

# Docker run command
docker_command='docker run --name tracee_$(hostname) --rm -d --privileged -v /etc/os-release:/host/etc/os-release:ro -v /lib/modules:/lib/modules:ro -v /usr/src:/usr/src:ro -v /tmp:/tmp -v /etc/os-release:/etc/os-release-host:ro -it aquasec/tracee:latest -e "read,write,bind,connect,accept,accept4,clone,close,creat,dup,dup2,dup3,execve,exit,exit_group,fork,open,openat,rename,renameat,unlink,unlinkat,vfork" -o json --scope container'

# Loop over each server and execute the docker command via SSH
for server in "${servers[@]}"
do
    echo "Running command on $server"
    ssh -o StrictHostKeyChecking=no "$server" "$docker_command"
done
