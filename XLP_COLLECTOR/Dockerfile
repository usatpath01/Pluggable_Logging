# Use an official Alpine Linux image as the base image
FROM alpine:latest

# Set environment variables
ENV LANG C.UTF-8

# Install necessary packages
RUN apk --no-cache add g++ make

# Create a directory for the server code
WORKDIR /app

# Copy the server C++ code to the container
COPY server.cpp /app/

# Compile the server code
RUN g++ -o server server.cpp

# Expose the port on which the server will listen
EXPOSE 8086

# Run the server when the container starts
CMD ["./server"]
