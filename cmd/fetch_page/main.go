package main

import (
	"fmt"
	"io"
	"net/http"
)

func main() {
	resp, err := http.Get("https://gallery.w33d.xyz/wall")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	
	body, _ := io.ReadAll(resp.Body)
	content := string(body)
	
	// Find images pointing to oss.w33d.xyz
	// Example: src="https://oss.w33d.xyz/..."
	// The content might be JS-generated or simply not matching regex.
	// Let's print the content to see.
	fmt.Println(content)
}
