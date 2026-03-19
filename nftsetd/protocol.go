package main

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"time"
)

type SetInfo struct {
	Family  string
	Table   string
	SetName string
}

type Config struct {
	Timeout time.Duration
	Set4    SetInfo
	Set6    SetInfo
}

const (
	OpSync    = 0
	OpComment = 1
	OpAddV4   = 4
	OpAddV6   = 6
)

// ReadNullTerminatedString reads a null-terminated string from reader
func ReadNullTerminatedString(r *bufio.Reader) (string, error) {
	var sb strings.Builder
	for {
		b, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		if b == 0 {
			break
		}
		sb.WriteByte(b)
	}
	return sb.String(), nil
}

// ParseConfig parses the initial config string
// Format: timeout:family,table,set4:family,table,set6
// Example: 300s:inet,mytable,myset4:inet,mytable,myset6
func ParseConfig(r *bufio.Reader) (*Config, error) {
	configStr, err := ReadNullTerminatedString(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read config string: %w", err)
	}

	parts := strings.Split(configStr, ":")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid config format: expected 3 parts separated by ':', got %d", len(parts))
	}

	timeout, err := time.ParseDuration(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid timeout format: %w", err)
	}

	set4, err := parseSetInfo(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid set4 info: %w", err)
	}

	set6, err := parseSetInfo(parts[2])
	if err != nil {
		return nil, fmt.Errorf("invalid set6 info: %w", err)
	}

	return &Config{
		Timeout: timeout,
		Set4:    set4,
		Set6:    set6,
	}, nil
}

func parseSetInfo(s string) (SetInfo, error) {
	parts := strings.Split(s, ",")
	if len(parts) != 3 {
		return SetInfo{}, fmt.Errorf("expected 3 comma-separated values, got %d", len(parts))
	}
	return SetInfo{
		Family:  parts[0],
		Table:   parts[1],
		SetName: parts[2],
	}, nil
}

// ReadOpcode reads the next opcode byte
func ReadOpcode(r *bufio.Reader) (byte, error) {
	return r.ReadByte()
}

// ReadIPv4 reads 4 bytes as an IPv4 address
func ReadIPv4(r *bufio.Reader) ([]byte, error) {
	ip := make([]byte, 4)
	_, err := io.ReadFull(r, ip)
	if err != nil {
		return nil, err
	}
	return ip, nil
}

// ReadIPv6 reads 16 bytes as an IPv6 address
func ReadIPv6(r *bufio.Reader) ([]byte, error) {
	ip := make([]byte, 16)
	_, err := io.ReadFull(r, ip)
	if err != nil {
		return nil, err
	}
	return ip, nil
}
