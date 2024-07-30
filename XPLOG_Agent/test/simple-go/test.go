package main

import (
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

func main() {
	// Initialize logger to write to stdout
	logger := log.New(os.Stdout, "", log.LstdFlags)

	// Make the HTTP request
	logger.Println("Making HTTP request to http://example.com")
	resp, err := http.Get("http://example.com")
	if err != nil {
		logger.Printf("Failed to make HTTP request: %s\n", err)
		return
	}
	defer resp.Body.Close()

	// Read the response body
	logger.Println("Reading response body")
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logger.Printf("Failed to read response body: %s\n", err)
		return
	}

	// Save the response body to a file
	logger.Println("Saving response to file")
	err = ioutil.WriteFile("response.txt", body, 0644)
	if err != nil {
		logger.Printf("Failed to write response to file: %s\n", err)
		return
	}

	logger.Println("HTTP request successful. Response saved to response.txt")
}
