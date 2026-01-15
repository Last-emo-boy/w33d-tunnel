package main

import (
	"flag"
	"fmt"
	"log"
	"net"
)

func main() {
	port := flag.Int("port", 2838, "Listen port")
	flag.Parse()

	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatal(err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	log.Printf("UDP Echo Server listening on %s", addr)
	log.Printf("Test with: nc -u <IP> %d", *port)

	buf := make([]byte, 1024)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Println("Read error:", err)
			continue
		}

		log.Printf("Received %d bytes from %s: %s", n, remoteAddr, string(buf[:n]))

		_, err = conn.WriteToUDP(buf[:n], remoteAddr)
		if err != nil {
			log.Println("Write error:", err)
		} else {
			log.Printf("Echoed back to %s", remoteAddr)
		}
	}
}
