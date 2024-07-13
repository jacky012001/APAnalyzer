# Use an official Node runtime as a parent image
FROM node:20

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install needed packages specified in package.json
RUN npm install

# Make port 3000 available for world outside this container
EXPOSE 3000

# Run the app when the container launches
CMD ["npm", "start"]