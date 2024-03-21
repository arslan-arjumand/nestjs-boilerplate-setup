#!/bin/bash

# Install the Nest CLI globally using npm
sudo npm install -g @nestjs/cli

# Copy the nginx configuration file to the nginx configuration directory
cp .platform/nginx/nginx.conf /etc/nginx/nginx.conf