# Start with a base image that has Go installed
FROM golang:1.17-alpine

# Set the working directory inside the container
WORKDIR /app

# Copy the Go file into the container
COPY test.go .

# Build the executable inside the container
RUN go build -o test test.go

# Set the command to run the executable
CMD ./test