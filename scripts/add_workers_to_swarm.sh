#!/bin/bash

# List of workers with their respective SSH credentials
workers=(
  "username@XXX.XX.XX.XXX"
  "username@XX.XX.XX.XXX"
)

# Join token and manager IP
# run: docker swarm join-token worker
worker_token="<worker-token>"
join_token="$worker_token"
manager_ip="XXX.XX.XX.XX"

# Port for Docker Swarm
swarm_port=2377

for worker in "${workers[@]}"; do
    echo "Adding $worker to the Docker Swarm"
    ssh "$worker" "docker swarm join --token $join_token $manager_ip:$swarm_port"
done
