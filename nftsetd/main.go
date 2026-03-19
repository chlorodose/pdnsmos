package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	sockPath := os.Getenv("NFTSETD_SOCK_PATH")
	if sockPath == "" {
		log.Fatal("NFTSETD_SOCK_PATH environment variable is not set")
	}

	// Remove existing socket file if it exists
	if err := os.Remove(sockPath); err != nil && !os.IsNotExist(err) {
		log.Fatalf("Failed to remove existing socket: %v", err)
	}

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", sockPath, err)
	}
	defer listener.Close()

	log.Printf("Listening on %s", sockPath)

	// Handle graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		<-sigCh
		log.Println("Shutting down...")
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			// Check if listener was closed
			if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "use of closed network connection" {
				break
			}
			log.Printf("Accept error: %v", err)
			continue
		}
		go HandleConnection(conn)
	}
}
