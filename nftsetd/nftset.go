package main

import (
	"fmt"
	"syscall"
	"time"

	"github.com/google/nftables"
)

type NFTManager struct {
	conn     *nftables.Conn
	set4     *nftables.Set
	set6     *nftables.Set
	timeout  time.Duration
	lastErr  syscall.Errno
}

func NewNFTManager(config *Config) (*NFTManager, error) {
	conn, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create nftables connection: %w", err)
	}

	set4, err := lookupSet(conn, config.Set4)
	if err != nil {
		conn.CloseLasting()
		return nil, fmt.Errorf("failed to lookup set4: %w", err)
	}

	set6, err := lookupSet(conn, config.Set6)
	if err != nil {
		conn.CloseLasting()
		return nil, fmt.Errorf("failed to lookup set6: %w", err)
	}

	return &NFTManager{
		conn:    conn,
		set4:    set4,
		set6:    set6,
		timeout: config.Timeout,
		lastErr: 0,
	}, nil
}

func lookupSet(conn *nftables.Conn, info SetInfo) (*nftables.Set, error) {
	family := parseFamily(info.Family)
	if family == 0 {
		return nil, fmt.Errorf("unsupported family: %s", info.Family)
	}

	table := &nftables.Table{
		Family: family,
		Name:   info.Table,
	}

	set, err := conn.GetSetByName(table, info.SetName)
	if err != nil {
		return nil, fmt.Errorf("failed to get set %s: %w", info.SetName, err)
	}

	return set, nil
}

func parseFamily(s string) nftables.TableFamily {
	switch s {
	case "inet":
		return nftables.TableFamilyINet
	case "ip":
		return nftables.TableFamilyIPv4
	case "ip6":
		return nftables.TableFamilyIPv6
	case "bridge":
		return nftables.TableFamilyBridge
	case "arp":
		return nftables.TableFamilyARP
	case "netdev":
		return nftables.TableFamilyNetdev
	default:
		return 0
	}
}

func (m *NFTManager) AddIPv4(ip []byte, comment string) {
	elem := nftables.SetElement{
		Key:     ip,
		Timeout: m.timeout,
	}
	if comment != "" {
		elem.Comment = comment
	}
	m.conn.SetAddElements(m.set4, []nftables.SetElement{elem})
}

func (m *NFTManager) AddIPv6(ip []byte, comment string) {
	elem := nftables.SetElement{
		Key:     ip,
		Timeout: m.timeout,
	}
	if comment != "" {
		elem.Comment = comment
	}
	m.conn.SetAddElements(m.set6, []nftables.SetElement{elem})
}

// Flush sends all pending operations to kernel and returns error code
func (m *NFTManager) Flush() uint32 {
	err := m.conn.Flush()
	if err != nil {
		if errno, ok := err.(syscall.Errno); ok {
			m.lastErr = errno
		} else {
			// Use a generic error code if we can't determine the errno
			m.lastErr = syscall.EIO
		}
	}

	errCode := uint32(m.lastErr)
	m.lastErr = 0
	return errCode
}

func (m *NFTManager) Close() {
	m.conn.CloseLasting()
}
