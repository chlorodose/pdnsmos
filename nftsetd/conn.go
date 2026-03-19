package main

import (
	"bufio"
	"encoding/binary"
	"io"
	"log"
	"net"
)

func HandleConnection(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Parse initial config
	config, err := ParseConfig(reader)
	if err != nil {
		log.Printf("Failed to parse config: %v", err)
		return
	}

	// Initialize NFTables manager
	mgr, err := NewNFTManager(config)
	if err != nil {
		log.Printf("Failed to initialize NFTManager: %v", err)
		return
	}
	defer mgr.Close()

	var currentComment string

	// Process commands
	for {
		opcode, err := ReadOpcode(reader)
		if err != nil {
			if err != io.EOF {
				log.Printf("Failed to read opcode: %v", err)
			}
			return
		}

		switch opcode {
		case OpSync:
			errCode := mgr.Flush()
			if err := binary.Write(conn, binary.BigEndian, errCode); err != nil {
				log.Printf("Failed to write sync response: %v", err)
				return
			}

		case OpComment:
			comment, err := ReadNullTerminatedString(reader)
			if err != nil {
				log.Printf("Failed to read comment: %v", err)
				return
			}
			currentComment = comment

		case OpAddV4:
			ip, err := ReadIPv4(reader)
			if err != nil {
				log.Printf("Failed to read IPv4: %v", err)
				return
			}
			mgr.AddIPv4(ip, currentComment)

		case OpAddV6:
			ip, err := ReadIPv6(reader)
			if err != nil {
				log.Printf("Failed to read IPv6: %v", err)
				return
			}
			mgr.AddIPv6(ip, currentComment)

		default:
			log.Printf("Unknown opcode: %d", opcode)
			return
		}
	}
}
