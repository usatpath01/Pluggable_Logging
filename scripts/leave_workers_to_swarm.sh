#!/bin/bash

# List of workers with their respective SSH credentials
workers=(
  "username@XX.XX.XX.XXX"
  "username@XX.XX.XX.XXX"
)


# Join token and manager IP
manager_ip="XX.XX.XX.XX"

# Port for Docker Swarm
swarm_port=2377

for worker in "${workers[@]}"; do
    echo "Leaving $worker to the Docker Swarm"
    ssh "$worker" "docker swarm leave"
done
