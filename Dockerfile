# Use a base image that includes Node.js
FROM node:18-alpine

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY dist /app

# Copy the package.json into the container at /app
COPY package*.json /app

# Copy the .env into the container at /app
COPY .env /app

# Install the dependencies
RUN npm install --omit=dev

# Run the app when the container launches
CMD ["node", "src/main.js"]

# Make port 3001 available to the world outside this container
EXPOSE 3001
