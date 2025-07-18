# Use a specific Node.js version as the base image for the builder stage
FROM node:22.17-alpine as builder

# Set the working directory inside the container
WORKDIR /app

# Copy package.json and package-lock.json files to install dependencies
COPY package*.json ./

# Install Node.js dependencies
RUN npm install

# Copy the entire project to the working directory
COPY . .

# Build the project
RUN npm run build

# Use the same specific Node.js version for the production stage
FROM node:22.17-alpine as production

# Set the working directory inside the container
WORKDIR /app

# Copy the dist folder from the builder stage
COPY --from=builder /app/dist ./dist

# Copy only the package files from the builder stage
COPY --from=builder /app/package*.json ./

# Install only production dependencies
RUN npm install --omit=dev

# Copy .env file if it exists
COPY --from=builder /app/.env ./.env

# Expose port 3001 for the application
EXPOSE 3001

# Command to run the NestJS app
CMD ["node", "dist/src/main.js"]
