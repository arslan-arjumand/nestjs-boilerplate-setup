#!/bin/bash

# echo "Starting Docker Compose..."

# Check if the directory exists
if [[ -d /home/ubuntu/ai-testing-system ]]; then
    echo "ai-testing-system folder found."
else
    echo "Creating ai-testing-system folder..."
    sudo mkdir -p /home/ubuntu/ai-testing-system
fi

# Copy the .env file if it exists
if [[ -f /home/ubuntu/.env ]]; then
    echo "Copying .env file..."
    sudo cp /home/ubuntu/.env /home/ubuntu/ai-testing-system/.env
else
    echo "Warning: .env file not found, proceeding without it."
fi

# Delete yarn.lock if it exists
if [[ -f /home/ubuntu/ai-testing-system/yarn.lock ]]; then
    echo "Delete yarn.lock file..."
    sudo rm -rf /home/ubuntu/ai-testing-system/yarn.lock
else
    echo "Warning: yarn.lock file not found, proceeding without it."
fi

# Delete package-lock.json if it exists
if [[ -f /home/ubuntu/ai-testing-system/package-lock.json ]]; then
    echo "Delete package-lock.json file..."
    sudo rm -rf /home/ubuntu/ai-testing-system/package-lock.json
else
    echo "Warning: package-lock.json file not found, proceeding without it."
fi

cd /home/ubuntu/ai-testing-system

npm install

npm run build

# Start Docker Compose if docker-compose.yml is present
if [[ -f docker-compose.yml ]]; then
    sudo docker compose up -d
    echo "Docker Compose started."
else
    echo "Error: docker-compose.yml not found. Docker Compose cannot start."
    exit 1
fi

# Exit with success status
echo "Done."
exit 0 