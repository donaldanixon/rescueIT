# Use the official Node.js 14 image as base
FROM node:latest

# Set the working directory in the container
WORKDIR /app

# Copy package.json and package-lock.json to the working directory
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy the rest of the application code
COPY index.js .

# Run the index.js file
CMD ["node", "index.js"]

# Expose port 8080
EXPOSE 8080
