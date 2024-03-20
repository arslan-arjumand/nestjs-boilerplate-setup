#!/bin/bash

# Remove all Docker cache
echo "Removing all Docker cache..."
sudo docker system prune -a -f
sudo docker builder prune --force --all

# Check if ai-testing-system directory exists
if [[ -d /home/ubuntu/ai-testing-system ]]; then
    echo "ai-testing-system directory found."

    # Check if docker-compose.yml file is present in the directory
    if [[ -f /home/ubuntu/ai-testing-system/docker-compose.yml ]]; then
        echo "docker-compose.yml found. Stopping Docker Compose..."
        (cd /home/ubuntu/ai-testing-system && sudo docker-compose down)
    fi

    # Delete the ai-testing-system directory
    echo "Deleting the ai-testing-system directory..."
    sudo rm -rf /home/ubuntu/ai-testing-system
else
    echo "ai-testing-system directory does not exist. No action taken."
fi


# Check if any docker containers are running
if [[ $(docker ps -q) ]]; then
    echo "Running containers found. Stopping them..."
    sudo docker stop $(docker ps -q)
fi

# Check if any docker containers are present
if [[ $(docker ps -a -q) ]]; then
    echo "Containers found. Removing them..."
    sudo docker rm $(docker ps -a -q)
fi

# Check if any docker images are present
if [[ $(docker images -q) ]]; then
    echo "Images found. Removing them..."
    sudo docker rmi -f $(docker images -aq)
fi

# Delete unnessary files
echo "Deleting unnessary files..."
sudo rm -rf /usr/local/share/.cache
sudo rm -rf /var/lib/docker/overlay2

# Exit with success status
echo "Done."
exit 0 